// Package telemetryjournal implements a durable queue foundation.
// It has no network listener, source reader, enrollment grant or runtime wiring.
package telemetryjournal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

var (
	ErrInvalid  = errors.New("telemetry journal invalid input")
	ErrConflict = errors.New("telemetry journal conflicting replay")
	ErrCorrupt  = errors.New("telemetry journal corruption")
	ErrCapacity = errors.New("telemetry journal capacity unavailable")
	ErrInUse    = errors.New("telemetry journal in use")
	ErrClosed   = errors.New("telemetry journal closed")
	ErrLost     = errors.New("telemetry journal explicit local loss")
	ErrRole     = errors.New("telemetry journal ownership mismatch")
)

type Role string

const (
	Node    Role = "NODE"
	Gateway Role = "GATEWAY"
)

type Lane string

const (
	Data    Lane = "DATA"
	Contact Lane = "CONTACT"
	Loss    Lane = "LOSS"
)

type Scope struct{ ClusterID, NodeID, EnrollmentID string }
type Envelope struct {
	Key                telemetry.BatchKey
	Digest             string
	CreatedAt          time.Time
	Lane               Lane
	Sources            []string
	Loss               []telemetry.SessionLoss
	BootID             string `json:"boot_id"`
	SigningKeyID       string `json:"signing_key_id"`
	EnrollmentRevision int64  `json:"enrollment_revision"`
}

// Verifier must perform protocol, signature and current admission-authority
// checks BEFORE the journal's replay lookup. No permissive production default.
type Verifier interface {
	Verify(context.Context, []byte) (Envelope, error)
}
type Limits struct {
	Total, Payload, Metadata, LossContact, Staging, MinimumFree int64
	MaxAge                                                      time.Duration
	MaxEntries                                                  int
}

func NodeLimits() Limits {
	return Limits{256 << 20, 176 << 20, 64 << 20, 8 << 20, 8 << 20, 1 << 30, 24 * time.Hour, 131072}
}
func GatewayLimits() Limits {
	return Limits{512 << 20, 384 << 20, 64 << 20, 32 << 20, 32 << 20, 1 << 30, 0, 131072}
}

type Options struct {
	Role            Role
	Scope           Scope
	Limits          Limits
	Verifier        Verifier
	SessionVerifier SessionVerifier
	ReleaseVerifier ReleaseVerifier
	RequireSessions bool
	GatewayBudget   *GatewayBudget
	SourceIDs       []string
	PublicKeys      []telemetry.NodeKey
	Now             func() time.Time
	fault           func(string) error
}
type Queue struct {
	mu      sync.Mutex
	db      *sql.DB
	lock    *os.File
	root    string
	opts    Options
	corrupt bool
}
type Entry struct {
	Key                 telemetry.BatchKey
	Digest              string
	CreatedAt, StoredAt time.Time
	Lane                Lane
	Bytes               int64
	Receipt             telemetry.Receipt
	State               string
	Loss                *LocalLoss
}
type LocalLoss struct {
	AffectedKey       telemetry.BatchKey `json:"affected_key"`
	Sources           []string           `json:"sources"`
	FromAt, ThroughAt *time.Time
	Count             *uint64
	Reason            string `json:"reason"`
}
type Stats struct {
	PhysicalBytes, PayloadBytes, ControlBytes, LossBytes int64
	Owned, Transferred, Lost                             int
	Corrupt                                              bool
}

func Open(root string, opts Options) (q *Queue, err error) {
	opts.PublicKeys = append([]telemetry.NodeKey(nil), opts.PublicKeys...)
	opts.SourceIDs = append([]string(nil), opts.SourceIDs...)
	sort.Strings(opts.SourceIDs)
	if !validSources(opts.SourceIDs) {
		return nil, ErrInvalid
	}
	if strings.ContainsAny(root, "?#") {
		return nil, ErrInvalid
	}
	if opts.Role != Node && opts.Role != Gateway || opts.ReleaseVerifier != nil && len(opts.PublicKeys) == 0 || opts.Verifier == nil || opts.RequireSessions && opts.SessionVerifier == nil || opts.Now == nil || !validScope(opts.Scope) || opts.Limits.Total < 1 || opts.Limits.Metadata < 1<<20 || opts.Limits.Staging < telemetry.MaxBatchBytes || opts.Limits.Payload < 1 || opts.Limits.MaxEntries < 1 || opts.Limits.LossContact < 1 || opts.Limits.MinimumFree < 0 || opts.Limits.Payload > opts.Limits.Total || opts.Limits.Metadata > opts.Limits.Total-opts.Limits.Payload || opts.Limits.LossContact > opts.Limits.Total-opts.Limits.Payload-opts.Limits.Metadata || opts.Limits.Staging > opts.Limits.Total-opts.Limits.Payload-opts.Limits.Metadata-opts.Limits.LossContact || opts.Role == Node && opts.Limits.MaxAge <= 0 {
		return nil, ErrInvalid
	}
	if opts.GatewayBudget != nil {
		if opts.Role != Gateway || !opts.GatewayBudget.contains(root) {
			return nil, ErrRole
		}
		unlock, budgetErr := opts.GatewayBudget.begin()
		if budgetErr != nil {
			return nil, budgetErr
		}
		defer unlock()
		if budgetErr = opts.GatewayBudget.reserve(0, 0, 0, 512<<10, 512<<10); budgetErr != nil {
			return nil, budgetErr
		}
	}
	if err = secureDirectory(root); err != nil {
		return nil, err
	}
	if err = secureDirectory(filepath.Join(root, "payload")); err != nil {
		return nil, err
	}
	_, priorLockErr := os.Lstat(filepath.Join(root, "owner.lock"))
	fd, e := unix.Open(filepath.Join(root, "owner.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, ErrCorrupt
	}
	lock := os.NewFile(uintptr(fd), "telemetry-lock")
	info, e := lock.Stat()
	if e != nil || !info.Mode().IsRegular() {
		lock.Close()
		return nil, ErrCorrupt
	}
	if lock.Chmod(0600) != nil {
		lock.Close()
		return nil, ErrCorrupt
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		lock.Close()
		return nil, ErrInUse
	}
	q = &Queue{lock: lock, root: root, opts: opts}
	opened := q
	defer func() {
		if err != nil {
			opened.close()
		}
	}()
	for _, name := range []string{"metadata.sqlite", "metadata.sqlite-wal", "metadata.sqlite-shm"} {
		p := filepath.Join(root, name)
		if i, e := os.Lstat(p); e == nil && (!i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0) {
			return nil, ErrCorrupt
		} else if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, ErrCorrupt
		}
	}
	markerPath := filepath.Join(root, "identity.json")
	marker, _ := json.Marshal(struct {
		Version         int
		Role            Role
		Scope           Scope
		RequireSessions bool
		SourceIDs       []string
	}{3, opts.Role, opts.Scope, opts.RequireSessions, opts.SourceIDs})
	markerInfo, markerErr := os.Lstat(markerPath)
	_, dbErr := os.Lstat(filepath.Join(root, "metadata.sqlite"))
	if markerErr == nil {
		if !markerInfo.Mode().IsRegular() || markerInfo.Mode().Perm() != 0600 || dbErr != nil {
			return nil, ErrCorrupt
		}
		existing, readErr := os.ReadFile(markerPath)
		if readErr != nil || !bytes.Equal(existing, marker) {
			return nil, ErrCorrupt
		}
	}
	if errors.Is(markerErr, os.ErrNotExist) {
		if priorLockErr == nil {
			return nil, ErrCorrupt
		}
		if !errors.Is(dbErr, os.ErrNotExist) {
			return nil, ErrCorrupt
		}
		entries, listErr := os.ReadDir(filepath.Join(root, "payload"))
		if listErr != nil || len(entries) != 0 {
			return nil, ErrCorrupt
		}
		fd, createErr := unix.Open(markerPath, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if createErr != nil {
			return nil, ErrCorrupt
		}
		f := os.NewFile(uintptr(fd), "telemetry-identity")
		_, writeErr := f.Write(marker)
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil || syncDirectory(root) != nil {
			return nil, ErrCorrupt
		}
	}
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		return nil, ErrCorrupt
	}
	path := filepath.Join(root, "metadata.sqlite")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, ErrCorrupt
	}
	if f.Chmod(0600) != nil {
		f.Close()
		return nil, ErrCorrupt
	}
	f.Close()
	q.db, e = sql.Open("sqlite", path)
	if e != nil {
		return nil, ErrCorrupt
	}
	q.db.SetMaxOpenConns(1)
	q.db.SetMaxIdleConns(1)
	for _, pragma := range []string{"locking_mode=EXCLUSIVE", "journal_mode=WAL", "synchronous=FULL", "busy_timeout=250", "foreign_keys=ON", "trusted_schema=OFF", "wal_autocheckpoint=16"} {
		if _, e = q.db.Exec("PRAGMA " + pragma); e != nil {
			return nil, ErrCorrupt
		}
	}
	// Reserve8 WAL pages and page-growth slack independently from payload bytes.
	var pages int64
	if e = q.db.QueryRow("PRAGMA max_page_count=" + decimal(opts.Limits.Metadata/4096-32)).Scan(&pages); e != nil || pages > opts.Limits.Metadata/4096-32 {
		return nil, ErrCapacity
	}
	if markerErr == nil {
		for _, name := range []string{"store", "items", "sessions", "pending", "item_rows", "session_identity", "source_dictionary", "items_insert", "items_update", "loss_order", "source_loss", "batch_loss", "retirement_state", "release_prefix", "release_ledger", "ownership_ranges", "retained_sessions", "release_loss", "loss_release_anchor", "session_handoffs", "final_loss", "public_keys"} {
			var found string
			if q.db.QueryRow(`SELECT name FROM sqlite_master WHERE name=?`, name).Scan(&found) != nil {
				return nil, ErrCorrupt
			}
		}
	}
	for _, statement := range append(append([]string(nil), compactSchema...), releaseSchema...) {
		if _, e = q.db.Exec(statement); e != nil {
			return nil, ErrCorrupt
		}
	}
	if markerErr != nil {
		for slot, name := range opts.SourceIDs {
			if _, e = q.db.Exec(`INSERT INTO source_dictionary(slot,name)VALUES(?,?)`, slot, name); e != nil {
				return nil, ErrCorrupt
			}
		}
	}
	rows, dictionaryErr := q.db.Query(`SELECT slot,name FROM source_dictionary ORDER BY slot`)
	if dictionaryErr != nil {
		return nil, ErrCorrupt
	}
	count := 0
	for rows.Next() {
		var slot int
		var name string
		if rows.Scan(&slot, &name) != nil || slot != count || count >= len(opts.SourceIDs) || name != opts.SourceIDs[count] {
			rows.Close()
			return nil, ErrCorrupt
		}
		count++
	}
	dictionaryErr = rows.Err()
	rows.Close()
	if dictionaryErr != nil || count != len(opts.SourceIDs) {
		return nil, ErrCorrupt
	}
	scope, _ := json.Marshal(opts.Scope)
	if _, e = q.db.Exec(`INSERT OR IGNORE INTO store VALUES(1,3,?,?)`, opts.Role, scope); e != nil {
		return nil, ErrCorrupt
	}
	var version int
	var role string
	var bound []byte
	if e = q.db.QueryRow(`SELECT version,role,scope FROM store WHERE singleton=1`).Scan(&version, &role, &bound); e != nil || version != 3 || role != string(opts.Role) || !bytes.Equal(bound, scope) {
		return nil, ErrCorrupt
	}
	var check string
	if e = q.db.QueryRow(`PRAGMA quick_check`).Scan(&check); e != nil || check != "ok" {
		return nil, ErrCorrupt
	}
	if err = q.registerPublicKeys(context.Background()); err != nil {
		return nil, err
	}
	if err = q.validateCompactState(); err != nil {
		return nil, err
	}
	if err = q.recoverSessions(context.Background()); err != nil {
		return nil, err
	}
	if err = q.recoverReleases(context.Background()); err != nil {
		return nil, err
	}
	if err = q.recoverSourceLosses(context.Background()); err != nil {
		return nil, err
	}
	if err = q.recover(context.Background()); err != nil {
		return nil, err
	}
	if physicalErr := q.checkPhysicalLimits(); physicalErr != nil {
		return nil, physicalErr
	}
	if err = syncDirectory(root); err != nil {
		return nil, err
	}
	if opts.GatewayBudget != nil {
		opts.GatewayBudget.queues[root] = true
	}
	return q, nil
}
func validScope(s Scope) bool {
	return validID(s.ClusterID) && validID(s.NodeID) && validID(s.EnrollmentID)
}
func validID(s string) bool {
	if s == "" || len(s) > 128 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r > 127 || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}
func validKey(k telemetry.BatchKey) bool {
	a, e := strconv.ParseUint(k.SessionEpoch, 10, 64)
	b, e2 := strconv.ParseUint(k.Sequence, 10, 64)
	return validScope(Scope{k.ClusterID, k.NodeID, k.EnrollmentID}) && validID(k.SessionID) && e == nil && e2 == nil && a > 0 && b > 0 && strconv.FormatUint(a, 10) == k.SessionEpoch && strconv.FormatUint(b, 10) == k.Sequence
}
func validSources(s []string) bool {
	if len(s) < 1 || len(s) > telemetry.MaxSources {
		return false
	}
	seen := map[string]bool{}
	for _, v := range s {
		if !validID(v) || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
func validDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func decimal(n int64) string {
	var b [32]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte(n%10) + '0'
		n /= 10
	}
	if i == len(b) {
		return "0"
	}
	return string(b[i:])
}

// secureDirectory traverses directory descriptors with NOFOLLOW. Root-owned
// sticky temporary ancestors are allowed; writable user/group ancestors are not.
// Darwin's root-owned /var and /tmp aliases are resolved explicitly before the
// descriptor walk. Other symlink components fail closed before directory creation.
func secureDirectory(path string) error {
	absolute, e := filepath.Abs(path)
	if e != nil || absolute == "/" {
		return ErrInvalid
	}
	if runtime.GOOS == "darwin" {
		for _, alias := range []string{"/var", "/tmp"} {
			if absolute == alias || strings.HasPrefix(absolute, alias+"/") {
				i, err := os.Lstat(alias)
				target, readErr := os.Readlink(alias)
				st, ok := iSys(i)
				if err != nil || readErr != nil || !ok || st.Uid != 0 || target != "private"+alias {
					return ErrCorrupt
				}
				absolute = "/private" + absolute
			}
		}
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrCorrupt
	}
	defer func() { unix.Close(fd) }()
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(absolute), "/"), "/")
	for index, part := range parts {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) {
			if unix.Mkdirat(fd, part, 0700) != nil || unix.Fsync(fd) != nil {
				return ErrCorrupt
			}
			next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			return ErrCorrupt
		}
		var st unix.Stat_t
		if unix.Fstat(next, &st) != nil {
			unix.Close(next)
			return ErrCorrupt
		}
		final := index == len(parts)-1
		trustedOwner := st.Uid == uint32(os.Geteuid()) || !final && st.Uid == 0
		stickyRoot := !final && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
		if !trustedOwner || st.Mode&0022 != 0 && !stickyRoot {
			unix.Close(next)
			return ErrCorrupt
		}
		if final && unix.Fchmod(next, 0700) != nil {
			unix.Close(next)
			return ErrCorrupt
		}
		unix.Close(fd)
		fd = next
	}
	return nil
}
func iSys(i os.FileInfo) (*syscall.Stat_t, bool) {
	if i == nil {
		return nil, false
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	return s, ok
}
func syncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return ErrCorrupt
	}
	defer f.Close()
	if f.Sync() != nil {
		return ErrCorrupt
	}
	return nil
}
func keyID(k telemetry.BatchKey) (string, []byte) {
	epoch, _ := strconv.ParseUint(k.SessionEpoch, 10, 64)
	sequence, _ := strconv.ParseUint(k.Sequence, 10, 64)
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[:8], epoch)
	binary.BigEndian.PutUint64(raw[8:], sequence)
	b, _ := json.Marshal(k)
	return hex.EncodeToString(raw[:]), b
}
func validFileID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && hex.EncodeToString(b) == s
}
func (q *Queue) fail(stage string) error {
	if q.opts.fault != nil {
		return q.opts.fault(stage)
	}
	return nil
}
func (q *Queue) check() error {
	if q.db == nil {
		return ErrClosed
	}
	if q.corrupt {
		return ErrCorrupt
	}
	return nil
}
func (q *Queue) markCorrupt() error { q.corrupt = true; return ErrCorrupt }
func (q *Queue) path(id string) string {
	var lane Lane
	if q.db.QueryRow(`SELECT lane FROM items WHERE id=?`, id).Scan(&lane) != nil {
		return filepath.Join(q.root, "payload", "invalid")
	}
	suffix := ".payload"
	if lane != Data {
		suffix = ".control"
	}
	return filepath.Join(q.root, "payload", id+suffix)
}

const columns = `key,digest,bytes,created,stored,lane,receipt,state`

func scanEntry(row interface{ Scan(...any) error }) (Entry, error) {
	var out Entry
	var key, receipt []byte
	var created, stored int64
	err := row.Scan(&key, &out.Digest, &out.Bytes, &created, &stored, &out.Lane, &receipt, &out.State)
	if err != nil {
		return out, err
	}
	if json.Unmarshal(key, &out.Key) != nil || json.Unmarshal(receipt, &out.Receipt) != nil {
		return out, ErrCorrupt
	}
	out.CreatedAt = time.Unix(0, created).UTC()
	out.StoredAt = time.Unix(0, stored).UTC()
	return out, nil
}

// Put never returns a receipt until both immutable file and metadata commit.
// Scope/signature/current authority are rechecked even for matching duplicates.
func (q *Queue) Put(ctx context.Context, body []byte) (telemetry.Receipt, error) {
	if len(body) == 0 || len(body) > telemetry.MaxBatchBytes {
		return telemetry.Receipt{}, ErrInvalid
	}
	// Admission proof runs before replay lookup and outside the queue mutex. A
	// caller may consult CheckBatchSession from its verifier without deadlocking.
	envelope, e := q.opts.Verifier.Verify(ctx, body)
	if e != nil {
		return telemetry.Receipt{}, ErrInvalid
	}
	unlock, budgetErr := q.beginBudget()
	if budgetErr != nil {
		return telemetry.Receipt{}, budgetErr
	}
	defer unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if e = q.check(); e != nil {
		return telemetry.Receipt{}, e
	}
	if !validKey(envelope.Key) || !validSources(envelope.Sources) || envelope.CreatedAt.Year() < 2020 || envelope.CreatedAt.Year() > 2200 || envelope.Key.ClusterID != q.opts.Scope.ClusterID || envelope.Key.NodeID != q.opts.Scope.NodeID || envelope.Key.EnrollmentID != q.opts.Scope.EnrollmentID || envelope.Lane != Data && envelope.Lane != Contact && envelope.Lane != Loss || !validDigest(envelope.Digest) {
		return telemetry.Receipt{}, ErrInvalid
	}
	id, key := keyID(envelope.Key)
	prior, e := scanEntry(q.db.QueryRowContext(ctx, `SELECT `+columns+` FROM items WHERE id=?`, id))
	if e == nil {
		if prior.Key != envelope.Key || prior.Digest != envelope.Digest {
			return telemetry.Receipt{}, ErrConflict
		}
		if prior.State == "LOST" {
			return telemetry.Receipt{}, ErrLost
		}
		if prior.State == "STAGING" {
			// No success receipt escaped this intent. A byte-identical retry can
			// finish a synced file, or safely replace only its unacknowledged temp.
			if _, readErr := q.read(id); readErr == nil {
				return q.finishIntent(ctx, id, envelope.Key, envelope.Digest)
			}
			q.corrupt = false
			for _, path := range []string{q.path(id), q.path(id) + ".tmp"} {
				if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
					return telemetry.Receipt{}, q.markCorrupt()
				}
			}
			if e = q.capacity(ctx, int64(len(body)), envelope.Lane, 0, id); e != nil {
				return telemetry.Receipt{}, e
			}
			wire := sha256.Sum256(body)
			if _, e = q.db.ExecContext(ctx, `UPDATE items SET wire=?,bytes=? WHERE id=? AND state='STAGING'`, hex.EncodeToString(wire[:]), len(body), id); e != nil {
				return telemetry.Receipt{}, ErrCapacity
			}
			return q.publish(ctx, id, envelope, body)
		}
		if prior.State == "OWNED" {
			if _, e = q.read(id); e != nil {
				return telemetry.Receipt{}, e
			}
		}
		return prior.Receipt, nil
	} else if !errors.Is(e, sql.ErrNoRows) {
		return telemetry.Receipt{}, q.markCorrupt()
	}
	if e = q.checkReleaseFence(ctx, envelope.Key); e != nil {
		return telemetry.Receipt{}, e
	}
	if q.opts.RequireSessions {
		if e = q.checkBatchSession(ctx, envelope.Key, envelope.BootID, envelope.SigningKeyID, envelope.EnrollmentRevision, envelope.Sources...); e != nil {
			return telemetry.Receipt{}, e
		}
	}
	if !q.allowedSources(envelope.Sources) {
		return telemetry.Receipt{}, ErrInvalid
	}
	if e = q.validateSourceLosses(ctx, envelope.Key, envelope.Loss, true); e != nil {
		return telemetry.Receipt{}, e
	}
	var pending []byte
	if len(envelope.Loss) > 0 {
		pending, _ = json.Marshal(envelope.Loss)
	}
	// Reserve both SQLite pages and WAL for the pending immutable signed facts
	// before writing the first intent, rather than noticing growth afterwards.
	if e = q.capacity(ctx, int64(len(body)), envelope.Lane, int64(3*len(pending))); e != nil {
		return telemetry.Receipt{}, e
	}
	now := q.opts.Now().UTC()
	sources, _ := json.Marshal(envelope.Sources)
	wire := sha256.Sum256(body)
	emptyReceipt, _ := json.Marshal(telemetry.Receipt{})
	if _, e = q.db.ExecContext(ctx, `INSERT INTO items(id,key,digest,wire,bytes,created,stored,lane,sources,state,receipt,pending_loss) VALUES(?,?,?,?,?,?,?,?,?,'STAGING',?,?)`, id, key, envelope.Digest, hex.EncodeToString(wire[:]), len(body), envelope.CreatedAt.UnixNano(), now.UnixNano(), envelope.Lane, sources, emptyReceipt, pending); e != nil {
		return telemetry.Receipt{}, ErrCapacity
	}
	if e = q.fail("intent_committed"); e != nil {
		return telemetry.Receipt{}, e
	}
	return q.publish(ctx, id, envelope, body)
}
func (q *Queue) publish(ctx context.Context, id string, envelope Envelope, body []byte) (telemetry.Receipt, error) {
	var e error
	temp := q.path(id) + ".tmp"
	fd, e := unix.Open(temp, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return telemetry.Receipt{}, ErrCapacity
	}
	f := os.NewFile(uintptr(fd), "telemetry-staging")
	_, e = f.Write(body)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return telemetry.Receipt{}, ErrCapacity
	}
	if e = q.fail("payload_synced"); e != nil {
		return telemetry.Receipt{}, e
	}
	if os.Rename(temp, q.path(id)) != nil {
		return telemetry.Receipt{}, ErrCapacity
	}
	if e = syncDirectory(filepath.Dir(temp)); e != nil {
		return telemetry.Receipt{}, e
	}
	if e = q.fail("payload_published"); e != nil {
		return telemetry.Receipt{}, e
	}
	receipt, e := q.finishIntent(ctx, id, envelope.Key, envelope.Digest)
	if e != nil {
		return telemetry.Receipt{}, e
	}
	if e = q.fail("receipt_committed"); e != nil {
		return telemetry.Receipt{}, e
	}
	return receipt, nil
}
func (q *Queue) finishIntent(ctx context.Context, id string, key telemetry.BatchKey, digest string) (telemetry.Receipt, error) {
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return telemetry.Receipt{}, ErrCapacity
	}
	r := telemetry.Receipt{ProtocolVersion: telemetry.ProtocolVersion, ID: "receipt-" + hex.EncodeToString(raw[:]), Key: key, Digest: digest, StoredAt: q.opts.Now().UTC(), Durability: string(q.opts.Role)}
	b, _ := json.Marshal(r)
	if e := q.mutationCapacity(ctx, int64(len(b))); e != nil {
		return telemetry.Receipt{}, e
	}
	var pending []byte
	if e := q.db.QueryRowContext(ctx, `SELECT pending_loss FROM items WHERE id=?`, id).Scan(&pending); e != nil {
		return telemetry.Receipt{}, q.markCorrupt()
	}
	var losses []telemetry.SessionLoss
	if len(pending) > 0 && json.Unmarshal(pending, &losses) != nil {
		return telemetry.Receipt{}, q.markCorrupt()
	}
	if e := q.validateSourceLosses(ctx, key, losses, false); e != nil {
		return telemetry.Receipt{}, e
	}
	if e := q.mutationCapacity(ctx, int64(len(b)+3*len(pending))); e != nil {
		return telemetry.Receipt{}, e
	}
	tx, e := q.db.BeginTx(ctx, nil)
	if e != nil {
		return telemetry.Receipt{}, ErrCapacity
	}
	defer tx.Rollback()
	for _, loss := range losses {
		body, digest := sourceLossBody(loss)
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO source_loss(id,epoch,source,digest,body)VALUES(?,?,?,?,?)`, loss.Range.ID, loss.Range.AffectedKey.SessionEpoch, loss.SourceID, digest, body); e != nil {
			return telemetry.Receipt{}, ErrCapacity
		}
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO batch_loss(item_id,loss_id)VALUES(?,?)`, id, loss.Range.ID); e != nil {
			return telemetry.Receipt{}, ErrCapacity
		}
	}
	if e = q.fail("losses_inserted"); e != nil {
		return telemetry.Receipt{}, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE items SET state='OWNED',receipt=?,pending_loss=NULL WHERE id=? AND state='STAGING'`, b, id); e != nil {
		return telemetry.Receipt{}, ErrCapacity
	}
	if e = tx.Commit(); e != nil {
		return telemetry.Receipt{}, ErrCapacity
	}
	return r, nil
}
func (q *Queue) read(id string) ([]byte, error) {
	var wire string
	var size int64
	if q.db.QueryRow(`SELECT wire,bytes FROM items WHERE id=?`, id).Scan(&wire, &size) != nil {
		return nil, q.markCorrupt()
	}
	b, e := readImmutable(q.path(id), size)
	if e != nil {
		return nil, q.markCorrupt()
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != wire {
		return nil, q.markCorrupt()
	}
	return b, nil
}
func (q *Queue) Read(ctx context.Context, key telemetry.BatchKey) ([]byte, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return nil, e
	}
	if !q.boundKey(key) {
		return nil, ErrInvalid
	}
	id, _ := keyID(key)
	var state string
	var original []byte
	var persisted telemetry.BatchKey
	if q.db.QueryRowContext(ctx, `SELECT state,key FROM items WHERE id=?`, id).Scan(&state, &original) != nil {
		return nil, ErrInvalid
	}
	if json.Unmarshal(original, &persisted) != nil {
		return nil, q.markCorrupt()
	}
	if persisted != key {
		return nil, ErrConflict
	}
	if state == "LOST" {
		return nil, ErrLost
	}
	if state != "OWNED" {
		return nil, ErrRole
	}
	return q.read(id)
}

func (q *Queue) Acknowledge(ctx context.Context, ack telemetry.Receipt, gatewayReceiptID string) error {
	unlock, budgetErr := q.beginBudget()
	if budgetErr != nil {
		return budgetErr
	}
	defer unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return e
	}
	expected := "GATEWAY"
	if q.opts.Role == Gateway {
		expected = "CLOUD"
	}
	if ack.ProtocolVersion != telemetry.ProtocolVersion || ack.Durability != expected || !validID(ack.ID) || !validKey(ack.Key) || !validDigest(ack.Digest) || ack.StoredAt.Year() < 2020 || ack.StoredAt.Year() > 2200 || ack.StoredAt.IsZero() {
		return ErrRole
	}
	id, _ := keyID(ack.Key)
	entry, e := scanEntry(q.db.QueryRowContext(ctx, `SELECT `+columns+` FROM items WHERE id=?`, id))
	if e != nil {
		return ErrInvalid
	}
	if !q.boundKey(ack.Key) || entry.Key != ack.Key || entry.Digest != ack.Digest || q.opts.Role == Gateway && entry.Receipt.ID != gatewayReceiptID {
		return ErrConflict
	}
	if entry.State == "LOST" {
		return ErrLost
	}
	if entry.State == "STAGING" {
		return ErrInvalid
	}
	ack.StoredAt = ack.StoredAt.UTC()
	b, _ := json.Marshal(ack)
	if entry.State == "TRANSFERRED" {
		var prior []byte
		if q.db.QueryRow(`SELECT ack FROM items WHERE id=?`, id).Scan(&prior) != nil {
			return q.markCorrupt()
		}
		var previous telemetry.Receipt
		if json.Unmarshal(prior, &previous) != nil {
			return q.markCorrupt()
		}
		if !sameReceipt(previous, ack) {
			return ErrConflict
		}
		return nil
	}
	if e = q.mutationCapacity(ctx, int64(len(b))); e != nil {
		return e
	}
	acknowledgedAt := q.opts.Now()
	if q.opts.Role == Gateway && ack.StoredAt.After(acknowledgedAt) {
		// A cloud clock ahead of the gateway must not shorten the exact receipt horizon.
		acknowledgedAt = ack.StoredAt
	}
	if _, e = q.db.ExecContext(ctx, `UPDATE items SET state='TRANSFERRED',ack=?,acked=? WHERE id=?`, b, acknowledgedAt.UnixNano(), id); e != nil {
		return ErrCapacity
	}
	if e = q.fail("ack_committed"); e != nil {
		return e
	}
	if os.Remove(q.path(id)) != nil {
		return q.markCorrupt()
	}
	return syncDirectory(filepath.Join(q.root, "payload"))
}
func (q *Queue) RecordLoss(ctx context.Context, key telemetry.BatchKey, reason string) error {
	unlock, budgetErr := q.beginBudget()
	if budgetErr != nil {
		return budgetErr
	}
	defer unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return e
	}
	if q.opts.Role != Node {
		return ErrRole
	}
	return q.lose(ctx, key, reason)
}
func (q *Queue) lose(ctx context.Context, key telemetry.BatchKey, reason string) error {
	if reason != "NODE_CAPACITY" && reason != "NODE_EXPIRED" && reason != "LOCAL_COMMIT_INTERRUPTED" {
		return ErrInvalid
	}
	if !q.boundKey(key) {
		return ErrInvalid
	}
	id, _ := keyID(key)
	var sources, original []byte
	var state string
	var persisted telemetry.BatchKey
	if q.db.QueryRowContext(ctx, `SELECT sources,state,key FROM items WHERE id=?`, id).Scan(&sources, &state, &original) != nil {
		return ErrInvalid
	}
	if json.Unmarshal(original, &persisted) != nil {
		return q.markCorrupt()
	}
	if persisted != key {
		return ErrConflict
	}
	if state == "LOST" {
		return nil
	}
	if state != "OWNED" && state != "STAGING" {
		return ErrRole
	}
	var names []string
	if json.Unmarshal(sources, &names) != nil {
		return q.markCorrupt()
	}
	loss := LocalLoss{AffectedKey: key, Sources: names, Reason: reason}
	body, _ := json.Marshal(loss)
	var used int64
	if q.db.QueryRow(`SELECT coalesce(sum(length(loss)),0) FROM items`).Scan(&used) != nil {
		return q.markCorrupt()
	}
	if used+int64(len(body)) > q.opts.Limits.LossContact/2 {
		return ErrCapacity
	}
	if e := q.mutationCapacity(ctx, int64(len(body))); e != nil {
		return e
	}
	if _, e := q.db.ExecContext(ctx, `UPDATE items SET state='LOST',loss=? WHERE id=?`, body, id); e != nil {
		return ErrCapacity
	}
	if e := q.fail("loss_committed"); e != nil {
		return e
	}
	if e := os.Remove(q.path(id)); e != nil && !errors.Is(e, os.ErrNotExist) {
		return q.markCorrupt()
	}
	_ = os.Remove(q.path(id) + ".tmp")
	return syncDirectory(filepath.Join(q.root, "payload"))
}
func (q *Queue) Losses(ctx context.Context) ([]LocalLoss, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return nil, e
	}
	rows, e := q.db.QueryContext(ctx, `SELECT loss FROM items WHERE state='LOST' ORDER BY stored,id LIMIT 128`)
	if e != nil {
		return nil, q.markCorrupt()
	}
	defer rows.Close()
	out := []LocalLoss{}
	for rows.Next() {
		var b []byte
		var l LocalLoss
		if rows.Scan(&b) != nil || json.Unmarshal(b, &l) != nil {
			return nil, q.markCorrupt()
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
func (q *Queue) Expire(ctx context.Context, now time.Time) error {
	unlock, budgetErr := q.beginBudget()
	if budgetErr != nil {
		return budgetErr
	}
	defer unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return e
	}
	if q.opts.Role != Node {
		return ErrRole
	}
	rows, e := q.db.QueryContext(ctx, `SELECT key FROM items WHERE state='OWNED' AND stored<=? ORDER BY stored,id LIMIT 128`, now.Add(-q.opts.Limits.MaxAge).UnixNano())
	if e != nil {
		return q.markCorrupt()
	}
	keys := []telemetry.BatchKey{}
	for rows.Next() {
		var b []byte
		var k telemetry.BatchKey
		if rows.Scan(&b) != nil || json.Unmarshal(b, &k) != nil {
			rows.Close()
			return q.markCorrupt()
		}
		keys = append(keys, k)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return q.markCorrupt()
	}
	for _, k := range keys {
		if e = q.lose(ctx, k, "NODE_EXPIRED"); e != nil {
			return e
		}
	}
	return nil
}
func (q *Queue) Next(ctx context.Context, limit int) ([]Entry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e := q.check(); e != nil {
		return nil, e
	}
	if limit < 1 || limit > 128 {
		return nil, ErrInvalid
	}
	rows, e := q.db.QueryContext(ctx, `SELECT `+columns+` FROM items WHERE state='OWNED' ORDER BY stored,id LIMIT ?`, limit)
	if e != nil {
		return nil, q.markCorrupt()
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		entry, e := scanEntry(rows)
		if e != nil {
			return nil, q.markCorrupt()
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}
func (q *Queue) Stats(ctx context.Context) (Stats, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.db == nil {
		return Stats{}, ErrClosed
	}
	return q.stats(ctx)
}
func (q *Queue) stats(ctx context.Context) (Stats, error) {
	s := Stats{Corrupt: q.corrupt}
	e := q.db.QueryRowContext(ctx, `SELECT coalesce(sum(CASE WHEN state IN ('OWNED','STAGING') AND lane='DATA' THEN bytes ELSE 0 END),0),coalesce(sum(CASE WHEN state IN ('OWNED','STAGING') AND lane<>'DATA' THEN bytes ELSE 0 END),0),coalesce(sum(length(loss)),0),coalesce(sum(state='OWNED'),0),coalesce(sum(state='TRANSFERRED'),0),coalesce(sum(state='LOST'),0) FROM items`).Scan(&s.PayloadBytes, &s.ControlBytes, &s.LossBytes, &s.Owned, &s.Transferred, &s.Lost)
	if e != nil {
		return s, ErrCorrupt
	}
	s.PhysicalBytes, e = physical(q.root)
	return s, e
}

// capacity charges allocated filesystem blocks, including directories and the
// simultaneous staging file. Metadata reservation includes pending signed loss
// facts as well as bounded SQLite page/WAL growth; no logical-byte-only cap.
func (q *Queue) capacity(ctx context.Context, size int64, lane Lane, metadata int64, replacing ...string) error {
	if _, e := q.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); e != nil {
		return ErrCapacity
	}
	s, e := aggregatePhysical(q.root)
	if e != nil {
		return q.markCorrupt()
	}
	var count int
	if q.db.QueryRowContext(ctx, `SELECT count(*) FROM items`).Scan(&count) != nil {
		return q.markCorrupt()
	}
	if len(replacing) == 1 {
		count--
	}
	if count >= q.opts.Limits.MaxEntries {
		return ErrCapacity
	}
	charge, fs, e := q.allocationCharge(size)
	if e != nil {
		return e
	}
	const reserve = 128 << 10
	metaCharge := metadata + reserve
	if s.Metadata > q.opts.Limits.Metadata-metaCharge || s.Staging > q.opts.Limits.Staging-charge || s.Total > q.opts.Limits.Total-charge-metaCharge {
		return ErrCapacity
	}
	if lane == Data && s.Payload > q.opts.Limits.Payload-charge || lane != Data && s.LossContact > q.opts.Limits.LossContact/2-charge {
		return ErrCapacity
	}
	if q.opts.GatewayBudget != nil {
		data, control := int64(0), int64(0)
		if lane == Data {
			data = charge
		} else {
			control = charge
		}
		if e = q.opts.GatewayBudget.reserve(data, control, charge, metaCharge, charge+metaCharge); e != nil {
			return e
		}
	}
	if int64(fs.Bavail)*int64(fs.Bsize)-charge-metaCharge < q.opts.Limits.MinimumFree {
		return ErrCapacity
	}
	return nil
}

// allocationCharge rounds a prospective immutable file up to the reported
// filesystem allocation unit. Unusual units fail closed rather than undercharge.
func (q *Queue) allocationCharge(size int64) (int64, unix.Statfs_t, error) {
	var fs unix.Statfs_t
	if size < 0 || unix.Statfs(q.root, &fs) != nil || fs.Bsize < 512 || fs.Bsize > 65536 {
		return 0, fs, ErrCapacity
	}
	unit := int64(fs.Bsize)
	return ((size + unit - 1) / unit) * unit, fs, nil
}

// mutationCapacity reserves physical metadata/WAL growth before ownership or
// allocator changes. Refusal preserves the prior durable owner and its bytes.
func (q *Queue) mutationCapacity(ctx context.Context, size int64) error {
	if _, e := q.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); e != nil {
		return ErrCapacity
	}
	s, e := aggregatePhysical(q.root)
	if e != nil {
		return q.markCorrupt()
	}
	charge, fs, e := q.allocationCharge(size)
	if e != nil {
		return e
	}
	const reserve = 128 << 10
	if s.Metadata > q.opts.Limits.Metadata-charge-reserve || s.Total > q.opts.Limits.Total-charge-reserve {
		return ErrCapacity
	}
	if q.opts.GatewayBudget != nil {
		if e = q.opts.GatewayBudget.reserve(0, 0, 0, charge+reserve, charge+reserve); e != nil {
			return e
		}
	}
	if int64(fs.Bavail)*int64(fs.Bsize)-charge-reserve < q.opts.Limits.MinimumFree {
		return ErrCapacity
	}
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func physical(root string) (int64, error) { s, e := aggregatePhysical(root); return s.Total, e }

type recoveryItem struct {
	id      string
	entry   Entry
	sources []string
}

func (q *Queue) recoveryPage(ctx context.Context, after string) ([]recoveryItem, error) {
	rows, e := q.db.QueryContext(ctx, `SELECT id,`+columns+`,ack,loss,sources FROM items WHERE id>? ORDER BY id LIMIT 256`, after)
	if e != nil {
		return nil, ErrCorrupt
	}
	list := make([]recoveryItem, 0, 256)
	for rows.Next() {
		var id string
		var key, receipt, ack, loss, sources []byte
		var out Entry
		var created, stored int64
		if rows.Scan(&id, &key, &out.Digest, &out.Bytes, &created, &stored, &out.Lane, &receipt, &out.State, &ack, &loss, &sources) != nil || json.Unmarshal(key, &out.Key) != nil || json.Unmarshal(receipt, &out.Receipt) != nil {
			rows.Close()
			return nil, ErrCorrupt
		}
		out.CreatedAt = time.Unix(0, created).UTC()
		out.StoredAt = time.Unix(0, stored).UTC()
		if out.CreatedAt.Year() < 2020 || out.CreatedAt.Year() > 2200 || out.StoredAt.Year() < 2020 || out.StoredAt.Year() > 2200 || out.Lane != Data && out.Lane != Contact && out.Lane != Loss {
			rows.Close()
			return nil, ErrCorrupt
		}
		if out.State != "STAGING" && out.State != "LOST" && (out.Receipt.ProtocolVersion != telemetry.ProtocolVersion || !validID(out.Receipt.ID) || out.Receipt.Key != out.Key || out.Receipt.Digest != out.Digest || out.Receipt.Durability != string(q.opts.Role) || out.Receipt.StoredAt.Year() < 2020 || out.Receipt.StoredAt.Year() > 2200) {
			rows.Close()
			return nil, ErrCorrupt
		}
		expected, _ := keyID(out.Key)
		if expected != id || !validKey(out.Key) || !validDigest(out.Digest) || out.Bytes < 1 || out.Bytes > telemetry.MaxBatchBytes {
			rows.Close()
			return nil, ErrCorrupt
		}
		var names []string
		if json.Unmarshal(sources, &names) != nil || !validSources(names) {
			rows.Close()
			return nil, ErrCorrupt
		}
		if out.State == "TRANSFERRED" {
			var a telemetry.Receipt
			expected := "GATEWAY"
			if q.opts.Role == Gateway {
				expected = "CLOUD"
			}
			if json.Unmarshal(ack, &a) != nil || a.ProtocolVersion != telemetry.ProtocolVersion || !validID(a.ID) || a.Key != out.Key || a.Digest != out.Digest || a.Durability != expected || a.StoredAt.Year() < 2020 || a.StoredAt.Year() > 2200 {
				rows.Close()
				return nil, ErrCorrupt
			}
		}
		if out.State == "LOST" {
			var l LocalLoss
			if q.opts.Role != Node || json.Unmarshal(loss, &l) != nil || l.AffectedKey != out.Key || !equalStrings(l.Sources, names) || l.Count != nil || l.FromAt != nil || l.ThroughAt != nil || l.Reason != "NODE_CAPACITY" && l.Reason != "NODE_EXPIRED" && l.Reason != "LOCAL_COMMIT_INTERRUPTED" {
				rows.Close()
				return nil, ErrCorrupt
			}
		}
		list = append(list, recoveryItem{id, out, names})
		if len(list) > 256 {
			rows.Close()
			return nil, ErrCapacity
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, ErrCorrupt
	}
	return list, nil
}
func (q *Queue) recover(ctx context.Context) error {
	// Two bounded passes validate every ownership fact before any destructive
	// recovery. The exclusive process lock keeps the id-cursor snapshot stable.
	for pass := 0; pass < 2; pass++ {
		after := ""
		count := 0
		for {
			page, e := q.recoveryPage(ctx, after)
			if e != nil {
				return e
			}
			if len(page) == 0 {
				break
			}
			count += len(page)
			if count > q.opts.Limits.MaxEntries {
				return ErrCapacity
			}
			for _, s := range page {
				after = s.id
				if pass == 0 {
					continue
				}
				switch s.entry.State {
				case "STAGING":
					if _, e = os.Lstat(q.path(s.id)); errors.Is(e, os.ErrNotExist) {
						if _, e = os.Lstat(q.path(s.id) + ".tmp"); e == nil {
							if _, e = q.readStaged(s.id); e == nil {
								if os.Rename(q.path(s.id)+".tmp", q.path(s.id)) != nil {
									return ErrCorrupt
								}
								if syncDirectory(filepath.Join(q.root, "payload")) != nil {
									return ErrCorrupt
								}
							}
						}
					}
					if _, e = q.read(s.id); e == nil {
						if _, e = q.finishIntent(ctx, s.id, s.entry.Key, s.entry.Digest); e != nil {
							return e
						}
					} else {
						q.corrupt = false
						if q.opts.Role == Node {
							if e = q.lose(ctx, s.entry.Key, "LOCAL_COMMIT_INTERRUPTED"); e != nil {
								return e
							}
						} else {
							// Gateway never acknowledged this staging intent; keep it for exact retry.
						}
					}
				case "OWNED":
					body, readErr := q.read(s.id)
					e = readErr
					if e != nil {
						return e
					}
					var sealed struct {
						Digest string `json:"digest"`
					}
					if json.Unmarshal(body, &sealed) != nil || sealed.Digest != s.entry.Digest {
						return ErrCorrupt
					}
					if q.opts.RequireSessions {
						var metadata struct {
							Key                telemetry.BatchKey `json:"key"`
							BootID             string             `json:"boot_id"`
							SigningKeyID       string             `json:"signing_key_id"`
							EnrollmentRevision int64              `json:"enrollment_revision"`
						}
						if json.Unmarshal(body, &metadata) != nil || metadata.Key != s.entry.Key || q.checkBatchSession(ctx, metadata.Key, metadata.BootID, metadata.SigningKeyID, metadata.EnrollmentRevision, s.sources...) != nil {
							return ErrCorrupt
						}
					}
				case "TRANSFERRED", "LOST":
					for _, p := range []string{q.path(s.id), q.path(s.id) + ".tmp"} {
						if e = os.Remove(p); e != nil && !errors.Is(e, os.ErrNotExist) {
							return ErrCorrupt
						}
					}
				default:
					return ErrCorrupt
				}

			}
		}
	}
	dir, e := os.Open(filepath.Join(q.root, "payload"))
	if e != nil {
		return ErrCorrupt
	}
	defer dir.Close()
	for {
		names, e := dir.Readdirnames(256)
		if e != nil && !errors.Is(e, io.EOF) {
			return ErrCorrupt
		}
		for _, name := range names {
			id := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, ".tmp"), ".payload"), ".control")
			if !validFileID(id) || name != id+".payload" && name != id+".payload.tmp" && name != id+".control" && name != id+".control.tmp" {
				return ErrCorrupt
			}
			var state string
			var lane Lane
			if q.db.QueryRowContext(ctx, `SELECT state,lane FROM items WHERE id=?`, id).Scan(&state, &lane) != nil {
				return ErrCorrupt
			}
			if lane == Data && strings.Contains(name, ".control") || lane != Data && strings.Contains(name, ".payload") {
				return ErrCorrupt
			}
			if state != "OWNED" && state != "STAGING" || strings.HasSuffix(name, ".tmp") && state != "STAGING" {
				return ErrCorrupt
			}
		}
		if errors.Is(e, io.EOF) {
			break
		}
	}
	return syncDirectory(filepath.Join(q.root, "payload"))
}
func (q *Queue) readStaged(id string) ([]byte, error) {
	var wire string
	var n int64
	if q.db.QueryRow(`SELECT wire,bytes FROM items WHERE id=?`, id).Scan(&wire, &n) != nil {
		return nil, ErrCorrupt
	}
	b, e := readImmutable(q.path(id)+".tmp", n)
	h := sha256.Sum256(b)
	if e != nil || hex.EncodeToString(h[:]) != wire {
		return nil, ErrCorrupt
	}
	return b, nil
}

// readImmutable validates the opened descriptor as well as the pathname; a
// replacement symlink/inode or unexpected mode/size never becomes trusted data.
func readImmutable(path string, size int64) ([]byte, error) {
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || size < 1 || size > telemetry.MaxBatchBytes || i.Size() != size {
		return nil, ErrCorrupt
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrCorrupt
	}
	f := os.NewFile(uintptr(fd), "telemetry-immutable")
	opened, e := f.Stat()
	if e != nil || !os.SameFile(i, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 || opened.Size() != size {
		f.Close()
		return nil, ErrCorrupt
	}
	b := make([]byte, size)
	_, readErr := io.ReadFull(f, b)
	var extra [1]byte
	n, extraErr := f.Read(extra[:])
	closeErr := f.Close()
	if readErr != nil || n != 0 || extraErr != io.EOF || closeErr != nil {
		return nil, ErrCorrupt
	}
	return b, nil
}

func (q *Queue) Close() error {
	unlock, e := q.beginBudget()
	if e != nil {
		return e
	}
	defer unlock()
	e = q.close()
	if q.opts.GatewayBudget != nil {
		delete(q.opts.GatewayBudget.queues, q.root)
	}
	return e
}
func (q *Queue) close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	var e error
	if q.db != nil {
		e = q.db.Close()
		q.db = nil
	}
	if q.lock != nil {
		e = errors.Join(e, q.lock.Close())
		q.lock = nil
	}
	return e
}

func allocated(i os.FileInfo) int64 {
	n := i.Size()
	if st, ok := i.Sys().(*syscall.Stat_t); ok && st.Blocks*512 > n {
		n = st.Blocks * 512
	}
	return n
}

// Binding exposes only immutable journal ownership/admission scope. It contains
// no signer material, source payload, filesystem path or runtime credentials.
type Binding struct {
	HasGatewayBudget bool
	Role             Role
	Scope            Scope
	RequireSessions  bool
}

func (q *Queue) Binding() Binding {
	q.mu.Lock()
	defer q.mu.Unlock()
	return Binding{Role: q.opts.Role, Scope: q.opts.Scope, RequireSessions: q.opts.RequireSessions, HasGatewayBudget: q.opts.GatewayBudget != nil}
}

func sameReceipt(a, b telemetry.Receipt) bool {
	return a.ProtocolVersion == b.ProtocolVersion && a.ID == b.ID && a.Key == b.Key && a.Digest == b.Digest && a.Durability == b.Durability && a.StoredAt.Equal(b.StoredAt)
}
