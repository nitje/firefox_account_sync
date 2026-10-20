package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	backupDir  = "/backups"
	volumeRoot = "/restore-volumes"
	currentEnv = "/project/.env"
	statusDir  = "/restore-status"
	listenAddr = ":8092"
	maxBody    = 128 * 1024
)

var (
	backupName = regexp.MustCompile(`^backup-([0-9]{8}T[0-9]{6}Z)(?:-([1-9][0-9]*))?$`)
	key        []byte
	jobMu      sync.Mutex
	jobRunning bool
)

type backupItem struct {
	Name      string `json:"name"`
	DateUTC   string `json:"date_utc"`
	SizeBytes int64  `json:"size_bytes"`
}

type statusPayload struct {
	Status       string `json:"status"`
	Phase        string `json:"phase,omitempty"`
	Timestamp    string `json:"timestamp"`
	Backup       string `json:"backup,omitempty"`
	SafetyBackup string `json:"safety_backup,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

type inspectResult struct {
	Backup        string   `json:"backup"`
	Valid         bool     `json:"valid"`
	CanRestore    bool     `json:"can_restore"`
	Checksums     bool     `json:"checksums_ok"`
	Archive       bool     `json:"archive_ok"`
	SQLGzip       bool     `json:"sql_gzip_ok"`
	EnvCompatible bool     `json:"env_compatible"`
	EnvMismatches []string `json:"env_mismatches"`
	ActiveWriters []string `json:"active_writers"`
	PendingBackup bool     `json:"pending_backup"`
	Detail        string   `json:"detail"`
}

type restoreRequest struct {
	Backup string `json:"backup"`
}

type restoreReply struct {
	Accepted bool          `json:"accepted"`
	Inspect  inspectResult `json:"inspect,omitempty"`
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		panic("missing environment: " + name)
	}
	return v
}

func nowISO() string { return time.Now().UTC().Format(time.RFC3339) }

func writeStatus(s statusPayload) {
	_ = os.MkdirAll(statusDir, 0755)
	s.Timestamp = nowISO()
	b, _ := json.Marshal(s)
	tmp := filepath.Join(statusDir, ".last.tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0644); err == nil {
		_ = os.Rename(tmp, filepath.Join(statusDir, "last.json"))
	}
}

func readStatus() statusPayload {
	b, err := os.ReadFile(filepath.Join(statusDir, "last.json"))
	if err != nil {
		return statusPayload{Status: "idle", Timestamp: nowISO(), Detail: "Noch keine Wiederherstellung ausgefuehrt"}
	}
	var s statusPayload
	if json.Unmarshal(b, &s) != nil {
		return statusPayload{Status: "unknown", Timestamp: nowISO(), Detail: "Statusdatei unlesbar"}
	}
	return s
}

func authorized(r *http.Request, body []byte) bool {
	stamp := r.Header.Get("X-Restore-Timestamp")
	sig := r.Header.Get("X-Restore-Signature")
	if len(stamp) != 10 || len(sig) != 64 {
		return false
	}
	var ts int64
	if _, err := fmt.Sscanf(stamp, "%d", &ts); err != nil {
		return false
	}
	if d := time.Now().Unix() - ts; d > 90 || d < -90 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s\n%s\n%s\n", r.Method, r.URL.Path, stamp)
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

func sendJSON(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func backupPath(name string) (string, error) {
	if !backupName.MatchString(name) {
		return "", errors.New("invalid backup name")
	}
	p := filepath.Join(backupDir, name)
	fi, err := os.Lstat(p)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("backup missing")
	}
	return p, nil
}

func listBackups() ([]backupItem, error) {
	ents, err := os.ReadDir(backupDir)
	if err != nil {
		return nil, err
	}
	out := make([]backupItem, 0)
	for _, ent := range ents {
		m := backupName.FindStringSubmatch(ent.Name())
		if m == nil || !ent.IsDir() {
			continue
		}
		p := filepath.Join(backupDir, ent.Name())
		var size int64
		members, err := os.ReadDir(p)
		if err != nil {
			continue
		}
		for _, f := range members {
			if info, err := f.Info(); err == nil && info.Mode().IsRegular() {
				size += info.Size()
			}
		}
		t, _ := time.Parse("20060102T150405Z", m[1])
		out = append(out, backupItem{Name: ent.Name(), DateUTC: t.UTC().Format("2006-01-02 15:04:05 UTC"), SizeBytes: size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

func expectedFiles(path string) error {
	for _, n := range []string{"fxa.sql.gz", "syncstorage.sql.gz", "tokenserver.sql.gz", "fxa-volumes.tar.gz", "dot-env.restore", "SHA256SUMS"} {
		fi, err := os.Lstat(filepath.Join(path, n))
		if err != nil || !fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("missing/invalid %s", n)
		}
	}
	return nil
}

func verifyChecksums(path string) error {
	raw, err := os.ReadFile(filepath.Join(path, "SHA256SUMS"))
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 {
			return errors.New("invalid SHA256SUMS")
		}
		name := strings.TrimPrefix(fields[1], "*")
		if strings.Contains(name, "/") || name == "SHA256SUMS" {
			return errors.New("invalid checksum name")
		}
		f, err := os.Open(filepath.Join(path, name))
		if err != nil {
			return err
		}
		h := sha256.New()
		_, cErr := io.Copy(h, f)
		_ = f.Close()
		if cErr != nil {
			return cErr
		}
		if !hmac.Equal([]byte(strings.ToLower(fields[0])), []byte(hex.EncodeToString(h.Sum(nil)))) {
			return fmt.Errorf("checksum mismatch: %s", name)
		}
		seen[name] = true
	}
	for _, n := range []string{"fxa.sql.gz", "syncstorage.sql.gz", "tokenserver.sql.gz", "fxa-volumes.tar.gz", "dot-env.restore"} {
		if !seen[n] {
			return fmt.Errorf("checksum missing: %s", n)
		}
	}
	return nil
}

func verifyGzip(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	_, err = io.Copy(io.Discard, gz)
	return err
}

func validateArchive(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	allowed := map[string]bool{"fxa-keys": true, "fxa-generated": true, "fxa-profile-images": true, "manager-state": true}
	seenRoots := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(strings.TrimPrefix(h.Name, "./"))
		if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
			return errors.New("unsafe tar path")
		}
		first := strings.Split(clean, string(os.PathSeparator))[0]
		if !allowed[first] {
			return fmt.Errorf("unexpected archive root: %s", first)
		}
		seenRoots[first] = true
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA && h.Typeflag != tar.TypeDir {
			return errors.New("symlink/device not allowed in archive")
		}
	}
	for root := range allowed {
		if !seenRoots[root] {
			return fmt.Errorf("archive root missing: %s", root)
		}
	}
	return nil
}

func parseDotEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	values := map[string]string{}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		i := strings.IndexByte(line, '=')
		if i < 1 {
			continue
		}
		k, v := strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		values[k] = v
	}
	return values, s.Err()
}

func envMismatches(path string) ([]string, error) {
	vals, err := parseDotEnv(filepath.Join(path, "dot-env.restore"))
	if err != nil {
		return nil, err
	}
	keys := []string{"FXA_BASE_DOMAIN", "FXA_VERSION", "FXA_AUTH_SECRET", "FXA_FLOW_KEY", "FXA_PROFILE_SECRET", "SYNC_VERSION", "SYNC_MASTER_SECRET", "SYNC_METRICS_HASH_SECRET", "SYNC_PUBLIC_URL"}
	out := []string{}
	for _, k := range keys {
		if vals[k] == "" || os.Getenv(k) == "" || vals[k] != os.Getenv(k) {
			out = append(out, k)
		}
	}
	return out, nil
}

type writer struct{ Name, Addr string }

var writers = []writer{
	{"syncserver", "syncserver:8000"}, {"fxa-auth-server", "fxa-auth-server:9000"},
	{"fxa-profile-server", "fxa-profile-server:1111"}, {"fxa-profile-worker", "fxa-profile-worker:1113"},
	{"fxa-profile-static", "fxa-profile-static:1112"}, {"fxa-content-server", "fxa-content-server:3030"},
	{"fxa-proxy", "fxa-proxy:80"}, {"fxa-signup-gate", "fxa-signup-gate:8090"},
}

func activeWriters() []string {
	out := []string{}
	for _, w := range writers {
		c, err := net.DialTimeout("tcp", w.Addr, 350*time.Millisecond)
		if err == nil {
			_ = c.Close()
			out = append(out, w.Name)
		}
	}
	return out
}
func hasPendingBackup() bool {
	m, _ := filepath.Glob(filepath.Join(backupDir, ".pending-*"))
	return len(m) > 0
}

func inspectBackup(name string, considerJob bool) inspectResult {
	r := inspectResult{Backup: name, EnvMismatches: []string{}, ActiveWriters: []string{}}
	p, err := backupPath(name)
	if err != nil {
		r.Detail = "Sicherung nicht gefunden/ungueltiger Name"
		return r
	}
	if err = expectedFiles(p); err != nil {
		r.Detail = err.Error()
		return r
	}
	if err = verifyChecksums(p); err != nil {
		r.Detail = "SHA256: " + err.Error()
		return r
	}
	r.Checksums = true
	for _, n := range []string{"fxa.sql.gz", "syncstorage.sql.gz", "tokenserver.sql.gz"} {
		if err = verifyGzip(filepath.Join(p, n)); err != nil {
			r.Detail = "GZIP: " + err.Error()
			return r
		}
	}
	r.SQLGzip = true
	if err = validateArchive(filepath.Join(p, "fxa-volumes.tar.gz")); err != nil {
		r.Detail = "Archiv: " + err.Error()
		return r
	}
	r.Archive = true
	mism, err := envMismatches(p)
	if err != nil {
		r.Detail = ".env-Pruefung fehlgeschlagen"
		return r
	}
	r.EnvMismatches = mism
	r.EnvCompatible = len(mism) == 0
	r.ActiveWriters = activeWriters()
	r.PendingBackup = hasPendingBackup()
	r.Valid = true
	busy := false
	jobMu.Lock()
	busy = jobRunning
	jobMu.Unlock()
	r.CanRestore = r.Valid && r.EnvCompatible && len(r.ActiveWriters) == 0 && !r.PendingBackup && (!considerJob || !busy)
	switch {
	case !r.EnvCompatible:
		r.Detail = "Backup passt nicht zu den identitaetskritischen Werten der aktuellen .env"
	case len(r.ActiveWriters) > 0:
		r.Detail = "Schreibende FxA/Sync-Dienste muessen in UGOS vor dem Restore gestoppt werden"
	case r.PendingBackup:
		r.Detail = "Ein Backup-Lauf ist noch aktiv"
	case considerJob && busy:
		r.Detail = "Eine Wiederherstellung laeuft bereits"
	default:
		r.Detail = "Backup geprueft und fuer Offline-Restore bereit"
	}
	return r
}

func runCmdEnv(stdin io.Reader, extraEnv []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), extraEnv...)
	return cmd.Run()
}
func dumpDB(out, host, user, pw string, dbs []string) error {
	args := []string{"--single-transaction", "--quick", "--routines", "--triggers", "--events", "--hex-blob", "--set-gtid-purged=OFF", "--no-tablespaces", "-h", host, "-u" + user, "--databases"}
	args = append(args, dbs...)
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd := exec.Command("mysqldump", args...)
	cmd.Stdout = f
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "MYSQL_PWD="+pw)
	return cmd.Run()
}
func gzipFile(path string) error { return runCmdEnv(nil, nil, "gzip", path) }
func copyFile(src, dst string, mode os.FileMode) error {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, in)
	ce := out.Close()
	if e != nil {
		return e
	}
	return ce
}
func writeSums(dir string) error {
	names := []string{"fxa.sql.gz", "syncstorage.sql.gz", "tokenserver.sql.gz", "fxa-volumes.tar.gz", "dot-env.restore"}
	var b strings.Builder
	for _, n := range names {
		f, e := os.Open(filepath.Join(dir, n))
		if e != nil {
			return e
		}
		h := sha256.New()
		_, e = io.Copy(h, f)
		_ = f.Close()
		if e != nil {
			return e
		}
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(h.Sum(nil)), n)
	}
	return os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(b.String()), 0644)
}
func uniqueBackupName() string {
	base := "backup-" + time.Now().UTC().Format("20060102T150405Z")
	n := base
	for i := 1; ; i++ {
		if _, e := os.Stat(filepath.Join(backupDir, n)); os.IsNotExist(e) {
			return n
		}
		n = fmt.Sprintf("%s-%d", base, i)
	}
}
func makeSafetyBackup() (string, error) {
	work, err := os.MkdirTemp(backupDir, ".pending-restore-safety-")
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(work)
		}
	}()
	if err = dumpDB(filepath.Join(work, "fxa.sql"), "fxa-db", "fxa", mustEnv("FXA_DB_PASSWORD"), []string{"fxa", "fxa_oauth", "fxa_profile", "pushbox"}); err != nil {
		return "", err
	}
	if err = gzipFile(filepath.Join(work, "fxa.sql")); err != nil {
		return "", err
	}
	if err = dumpDB(filepath.Join(work, "syncstorage.sql"), "sync-db", "sync", mustEnv("SYNC_DB_PASSWORD"), []string{"syncstorage"}); err != nil {
		return "", err
	}
	if err = gzipFile(filepath.Join(work, "syncstorage.sql")); err != nil {
		return "", err
	}
	if err = dumpDB(filepath.Join(work, "tokenserver.sql"), "token-db", "token", mustEnv("TOKEN_DB_PASSWORD"), []string{"tokenserver"}); err != nil {
		return "", err
	}
	if err = gzipFile(filepath.Join(work, "tokenserver.sql")); err != nil {
		return "", err
	}
	if err = runCmdEnv(nil, nil, "tar", "-C", volumeRoot, "-czf", filepath.Join(work, "fxa-volumes.tar.gz"), "fxa-keys", "fxa-generated", "fxa-profile-images", "manager-state"); err != nil {
		return "", err
	}
	if err = copyFile(currentEnv, filepath.Join(work, "dot-env.restore"), 0600); err != nil {
		return "", err
	}
	if err = writeSums(work); err != nil {
		return "", err
	}
	name := uniqueBackupName()
	if err = os.Rename(work, filepath.Join(backupDir, name)); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

func resetDB(host, user, pw string, dbs map[string]string) error {
	var sql strings.Builder
	sql.WriteString("SET FOREIGN_KEY_CHECKS=0;")
	keys := make([]string, 0, len(dbs))
	for n := range dbs {
		keys = append(keys, n)
	}
	sort.Strings(keys)
	for _, n := range keys {
		fmt.Fprintf(&sql, "DROP DATABASE IF EXISTS `%s`; CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE %s;", n, n, dbs[n])
	}
	return runCmdEnv(strings.NewReader(sql.String()), []string{"MYSQL_PWD=" + pw}, "mysql", "--connect-timeout=10", "-h", host, "-u"+user)
}

func filteredSQL(path string) (io.ReadCloser, <-chan error, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		defer close(done)
		defer f.Close()
		defer gz.Close()
		br := bufio.NewReaderSize(gz, 128*1024)
		var outErr error
		for {
			line, e := br.ReadString('\n')
			trim := strings.TrimSpace(line)
			if !strings.HasPrefix(strings.ToUpper(trim), "CREATE DATABASE ") && !strings.HasPrefix(strings.ToUpper(trim), "DROP DATABASE ") {
				if _, w := io.WriteString(pw, line); w != nil {
					outErr = w
					break
				}
			}
			if errors.Is(e, io.EOF) {
				break
			}
			if e != nil {
				outErr = e
				break
			}
		}
		_ = pw.CloseWithError(outErr)
		done <- outErr
	}()
	return pr, done, nil
}
func importDump(path, host, user, pw string) error {
	r, done, err := filteredSQL(path)
	if err != nil {
		return err
	}
	cmdErr := runCmdEnv(r, []string{"MYSQL_PWD=" + pw}, "mysql", "--connect-timeout=10", "-h", host, "-u"+user)
	_ = r.Close()
	filterErr := <-done
	if cmdErr != nil {
		return cmdErr
	}
	return filterErr
}

func clearDir(path string) error {
	ents, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err = os.RemoveAll(filepath.Join(path, e.Name())); err != nil {
			return err
		}
	}
	return nil
}
func restoreVolumes(archive string) error {
	if err := validateArchive(archive); err != nil {
		return err
	}
	roots := []string{"fxa-keys", "fxa-generated", "fxa-profile-images", "manager-state"}
	for _, r := range roots {
		if err := clearDir(filepath.Join(volumeRoot, r)); err != nil {
			return err
		}
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return e
		}
		clean := filepath.Clean(strings.TrimPrefix(h.Name, "./"))
		dest := filepath.Join(volumeRoot, clean)
		if !strings.HasPrefix(dest, volumeRoot+string(os.PathSeparator)) {
			return errors.New("unsafe extraction")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if e = os.MkdirAll(dest, os.FileMode(h.Mode)); e != nil {
				return e
			}
		case tar.TypeReg, tar.TypeRegA:
			if e = os.MkdirAll(filepath.Dir(dest), 0755); e != nil {
				return e
			}
			out, e := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(h.Mode))
			if e != nil {
				return e
			}
			_, e = io.Copy(out, tr)
			ce := out.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		default:
			return errors.New("unsupported archive member")
		}
		_ = os.Chown(dest, h.Uid, h.Gid)
		_ = os.Chmod(dest, os.FileMode(h.Mode))
	}
	return nil
}
func flushRedis() error {
	c, err := net.DialTimeout("tcp", "fxa-redis:6379", 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte("*1\r\n$8\r\nFLUSHALL\r\n")); err != nil {
		return err
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(buf[:n]), "+OK") {
		return errors.New("redis flush rejected")
	}
	return nil
}

func restoreData(name string) error {
	p, err := backupPath(name)
	if err != nil {
		return err
	}
	if err = resetDB("fxa-db", "fxa", mustEnv("FXA_DB_PASSWORD"), map[string]string{"fxa": "utf8mb4_unicode_ci", "fxa_oauth": "utf8mb4_unicode_ci", "fxa_profile": "utf8mb4_unicode_ci", "pushbox": "utf8mb4_unicode_ci"}); err != nil {
		return fmt.Errorf("fxa reset: %w", err)
	}
	if err = importDump(filepath.Join(p, "fxa.sql.gz"), "fxa-db", "fxa", mustEnv("FXA_DB_PASSWORD")); err != nil {
		return fmt.Errorf("fxa import: %w", err)
	}
	if err = resetDB("sync-db", "sync", mustEnv("SYNC_DB_PASSWORD"), map[string]string{"syncstorage": "utf8mb4_0900_ai_ci"}); err != nil {
		return fmt.Errorf("sync reset: %w", err)
	}
	if err = importDump(filepath.Join(p, "syncstorage.sql.gz"), "sync-db", "sync", mustEnv("SYNC_DB_PASSWORD")); err != nil {
		return fmt.Errorf("sync import: %w", err)
	}
	if err = resetDB("token-db", "token", mustEnv("TOKEN_DB_PASSWORD"), map[string]string{"tokenserver": "utf8mb4_0900_ai_ci"}); err != nil {
		return fmt.Errorf("token reset: %w", err)
	}
	if err = importDump(filepath.Join(p, "tokenserver.sql.gz"), "token-db", "token", mustEnv("TOKEN_DB_PASSWORD")); err != nil {
		return fmt.Errorf("token import: %w", err)
	}
	if err = restoreVolumes(filepath.Join(p, "fxa-volumes.tar.gz")); err != nil {
		return fmt.Errorf("volumes: %w", err)
	}
	if err = flushRedis(); err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	return nil
}

func restoreJob(target string) {
	removeLock := true
	defer func() {
		jobMu.Lock()
		jobRunning = false
		jobMu.Unlock()
		if removeLock {
			_ = os.Remove(filepath.Join(statusDir, "restore.lock"))
		}
	}()
	_ = os.MkdirAll(statusDir, 0755)
	_ = os.WriteFile(filepath.Join(statusDir, "restore.lock"), []byte(nowISO()+"\n"), 0644)
	pre := inspectBackup(target, false)
	if !pre.Valid || !pre.EnvCompatible || len(pre.ActiveWriters) > 0 || pre.PendingBackup {
		writeStatus(statusPayload{Status: "failed", Phase: "preflight", Backup: target, Detail: pre.Detail})
		return
	}
	writeStatus(statusPayload{Status: "running", Phase: "safety_backup", Backup: target, Detail: "Vor dem Restore wird automatisch eine Rueckfall-Sicherung erstellt"})
	safety, err := makeSafetyBackup()
	if err != nil {
		writeStatus(statusPayload{Status: "failed", Phase: "safety_backup", Backup: target, Detail: "Rueckfall-Sicherung fehlgeschlagen; Restore nicht begonnen"})
		return
	}
	writeStatus(statusPayload{Status: "running", Phase: "restore", Backup: target, SafetyBackup: safety, Detail: "Datenbanken und FxA-Volumes werden wiederhergestellt"})
	if err = restoreData(target); err == nil {
		writeStatus(statusPayload{Status: "success", Phase: "complete", Backup: target, SafetyBackup: safety, Detail: "Restore abgeschlossen; gestoppte FxA/Sync-Dienste jetzt in UGOS wieder starten"})
		return
	}
	writeStatus(statusPayload{Status: "running", Phase: "rollback", Backup: target, SafetyBackup: safety, Detail: "Restore fehlgeschlagen; automatische Rueckkehr zur Vorher-Sicherung laeuft"})
	if rb := restoreData(safety); rb == nil {
		writeStatus(statusPayload{Status: "failed_rolled_back", Phase: "rollback_complete", Backup: target, SafetyBackup: safety, Detail: "Restore fehlgeschlagen; vorheriger Zustand wurde automatisch wiederhergestellt"})
	} else {
		removeLock = false
		_ = os.WriteFile(filepath.Join(statusDir, "restore.lock"), []byte("FAILED "+nowISO()+"\n"), 0644)
		writeStatus(statusPayload{Status: "failed_rollback_failed", Phase: "rollback_failed", Backup: target, SafetyBackup: safety, Detail: "Restore UND automatische Rueckkehr fehlgeschlagen; Restore-Lock bleibt gesetzt. Dienste nicht starten und Logs/Backups pruefen"})
	}
}

func main() {
	admin := mustEnv("ADMIN_PASSWORD")
	sum := sha256.Sum256(append([]byte("fxa-restore-management-v1\x00"), []byte(admin)...))
	key = sum[:]
	for _, e := range []string{"FXA_DB_PASSWORD", "SYNC_DB_PASSWORD", "TOKEN_DB_PASSWORD", "FXA_BASE_DOMAIN", "FXA_VERSION", "FXA_AUTH_SECRET", "FXA_FLOW_KEY", "FXA_PROFILE_SECRET", "SYNC_VERSION", "SYNC_MASTER_SECRET", "SYNC_METRICS_HASH_SECRET", "SYNC_PUBLIC_URL"} {
		mustEnv(e)
	}
	_ = os.MkdirAll(statusDir, 0755)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { sendJSON(w, 200, map[string]bool{"ok": true}) })
	http.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || !authorized(r, nil) {
			sendJSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		b, e := listBackups()
		if e != nil {
			sendJSON(w, 503, map[string]string{"error": "inventory_unavailable"})
			return
		}
		sendJSON(w, 200, map[string]any{"backups": b, "status": readStatus()})
	})
	http.HandleFunc("/inspect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			sendJSON(w, 405, map[string]string{"error": "method"})
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if e != nil || len(body) > maxBody || !authorized(r, body) {
			sendJSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		var q restoreRequest
		if json.Unmarshal(body, &q) != nil {
			sendJSON(w, 400, map[string]string{"error": "invalid"})
			return
		}
		sendJSON(w, 200, inspectBackup(q.Backup, true))
	})
	http.HandleFunc("/restore", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			sendJSON(w, 405, map[string]string{"error": "method"})
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if e != nil || len(body) > maxBody || !authorized(r, body) {
			sendJSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		var q restoreRequest
		if json.Unmarshal(body, &q) != nil {
			sendJSON(w, 400, map[string]string{"error": "invalid"})
			return
		}
		pre := inspectBackup(q.Backup, true)
		if !pre.CanRestore {
			sendJSON(w, 409, restoreReply{Accepted: false, Inspect: pre})
			return
		}
		jobMu.Lock()
		if jobRunning {
			jobMu.Unlock()
			sendJSON(w, 409, map[string]string{"error": "busy"})
			return
		}
		jobRunning = true
		jobMu.Unlock()
		go restoreJob(q.Backup)
		sendJSON(w, 202, restoreReply{Accepted: true, Inspect: pre})
	})
	fmt.Println("Firefox Restore-Admin 0.6.0 (internal only) listening on 8092")
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		panic(err)
	}
}
