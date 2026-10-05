// Package store is the SQLite persistence layer. It only ever sees opaque
// ciphertext envelopes, pseudonymous identifiers and public rating aggregates.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrQuota    = errors.New("quota")
	ErrTooLarge = errors.New("too large")
	ErrExists   = errors.New("exists")
	ErrStale    = errors.New("stale")
	ErrFull     = errors.New("full")
)

// Quota caps resource use per group.
type Quota struct {
	MaxDocs         int
	MaxRows         int // live documents + tombstones
	MaxBytes        int64
	MaxBlobSize     int64
	MaxBlobs        int
	BlobMinCost     int64 // each blob counts for at least this many bytes
	MaxMembers      int
	MaxActiveTokens int
}

type Store struct {
	db      *sql.DB
	blobDir string
	now     func() time.Time
	blobMu  sync.Mutex // serialises blob file + accounting changes
}

func Open(path, blobDir string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		return nil, err
	}
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(1)"
	if path == ":memory:" {
		dsn = "file::memory:?cache=shared&_pragma=foreign_keys(1)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, blobDir: blobDir, now: time.Now}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS groups(
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  last_activity INTEGER NOT NULL,
  seq INTEGER NOT NULL DEFAULT 0,
  docs INTEGER NOT NULL DEFAULT 0,
  rows INTEGER NOT NULL DEFAULT 0,
  bytes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS members(
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  pub TEXT NOT NULL,
  name_enc TEXT NOT NULL DEFAULT '',
  owner INTEGER NOT NULL DEFAULT 0,
  joined_at INTEGER NOT NULL,
  PRIMARY KEY(group_id, pub)
);
CREATE TABLE IF NOT EXISTS join_tokens(
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(group_id, token_hash)
);
CREATE TABLE IF NOT EXISTS docs(
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  collection TEXT NOT NULL,
  doc_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  env BLOB,
  size INTEGER NOT NULL DEFAULT 0,
  deleted INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(group_id, collection, doc_id)
);
CREATE INDEX IF NOT EXISTS docs_seq ON docs(group_id, seq);
CREATE TABLE IF NOT EXISTS blobs(
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  blob_id TEXT NOT NULL,
  size INTEGER NOT NULL,
  cost INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(group_id, blob_id)
);
CREATE TABLE IF NOT EXISTS ratings(
  content_key TEXT NOT NULL,
  pseudonym TEXT NOT NULL,
  rating REAL,
  ts INTEGER NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(content_key, pseudonym)
);`)
	return err
}

func (s *Store) tx(f func(*sql.Tx) error) error {
	t, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := f(t); err != nil {
		_ = t.Rollback()
		return err
	}
	return t.Commit()
}

// ---------- groups & members ----------

// CreateGroup creates the group and its owner member atomically.
func (s *Store) CreateGroup(id, ownerPub, nameEnc string) error {
	n := s.now().Unix()
	return s.tx(func(t *sql.Tx) error {
		if _, err := t.Exec(`INSERT INTO groups(id,created_at,last_activity) VALUES(?,?,?)`, id, n, n); err != nil {
			return ErrExists
		}
		_, err := t.Exec(`INSERT INTO members(group_id,pub,name_enc,owner,joined_at) VALUES(?,?,?,1,?)`, id, ownerPub, nameEnc, n)
		return err
	})
}

func (s *Store) IsMember(gid, pub string) (member, owner bool, err error) {
	var o int
	err = s.db.QueryRow(`SELECT owner FROM members WHERE group_id=? AND pub=?`, gid, pub).Scan(&o)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	return err == nil, o == 1, err
}

// AddJoinToken stores a hashed token, refusing when too many are still valid.
func (s *Store) AddJoinToken(gid, tokenHash string, expires time.Time, maxActive int) error {
	return s.tx(func(t *sql.Tx) error {
		var n int
		if err := t.QueryRow(`SELECT COUNT(*) FROM join_tokens WHERE group_id=? AND used=0 AND expires_at>?`, gid, s.now().Unix()).Scan(&n); err != nil {
			return err
		}
		if n >= maxActive {
			return ErrQuota
		}
		_, err := t.Exec(`INSERT INTO join_tokens(group_id,token_hash,expires_at) VALUES(?,?,?)`, gid, tokenHash, expires.Unix())
		return err
	})
}

// Join consumes a valid single-use token and registers the device. Unknown,
// used and expired tokens are indistinguishable (returns false). A full group
// returns ErrQuota without consuming the token.
func (s *Store) Join(gid, tokenHash, pub, nameEnc string, maxMembers int) (bool, error) {
	ok := false
	err := s.tx(func(t *sql.Tx) error {
		n := s.now().Unix()
		var members int
		if err := t.QueryRow(`SELECT COUNT(*) FROM members WHERE group_id=?`, gid).Scan(&members); err != nil {
			return err
		}
		res, err := t.Exec(`UPDATE join_tokens SET used=1 WHERE group_id=? AND token_hash=? AND used=0 AND expires_at>?`, gid, tokenHash, n)
		if err != nil {
			return err
		}
		if c, _ := res.RowsAffected(); c != 1 {
			return nil
		}
		if members >= maxMembers {
			return ErrQuota
		}
		if _, err := t.Exec(`INSERT OR IGNORE INTO members(group_id,pub,name_enc,joined_at) VALUES(?,?,?,?)`, gid, pub, nameEnc, n); err != nil {
			return err
		}
		ok = true
		return nil
	})
	return ok, err
}

type Member struct {
	Device   string `json:"device"`
	NameEnc  string `json:"nameEnc"`
	Owner    bool   `json:"owner"`
	JoinedAt int64  `json:"joinedAt"`
}

func (s *Store) Members(gid string) ([]Member, error) {
	rows, err := s.db.Query(`SELECT pub,name_enc,owner,joined_at FROM members WHERE group_id=? ORDER BY joined_at,pub`, gid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Member{}
	for rows.Next() {
		var m Member
		var o int
		if err := rows.Scan(&m.Device, &m.NameEnc, &o, &m.JoinedAt); err != nil {
			return nil, err
		}
		m.Owner = o == 1
		out = append(out, m)
	}
	return out, rows.Err()
}

// RemoveMember deletes a non-owner member.
func (s *Store) RemoveMember(gid, pub string) error {
	res, err := s.db.Exec(`DELETE FROM members WHERE group_id=? AND pub=? AND owner=0`, gid, pub)
	if err != nil {
		return err
	}
	if c, _ := res.RowsAffected(); c == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Touch(gid string) {
	_, _ = s.db.Exec(`UPDATE groups SET last_activity=? WHERE id=?`, s.now().Unix(), gid)
}

type Info struct {
	Seq          int64 `json:"seq"`
	Docs         int   `json:"docs"`
	Bytes        int64 `json:"bytes"`
	LastActivity int64 `json:"lastActivity"`
	Members      int   `json:"members"`
}

func (s *Store) Info(gid string) (Info, error) {
	var i Info
	err := s.db.QueryRow(`SELECT seq,docs,bytes,last_activity,(SELECT COUNT(*) FROM members WHERE group_id=?) FROM groups WHERE id=?`, gid, gid).
		Scan(&i.Seq, &i.Docs, &i.Bytes, &i.LastActivity, &i.Members)
	if errors.Is(err, sql.ErrNoRows) {
		return i, ErrNotFound
	}
	return i, err
}

// PurgeGroup removes a group, its documents, members, tokens and blobs.
func (s *Store) PurgeGroup(gid string) error {
	s.blobMu.Lock()
	defer s.blobMu.Unlock()
	if _, err := s.db.Exec(`DELETE FROM groups WHERE id=?`, gid); err != nil {
		return err
	}
	return os.RemoveAll(s.blobGroupDir(gid))
}

// PurgeInactive deletes groups with no activity since cutoff; returns ids.
func (s *Store) PurgeInactive(cutoff time.Time) ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM groups WHERE last_activity<?`, cutoff.Unix())
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if err := s.PurgeGroup(id); err != nil {
			return ids, err
		}
	}
	_, _ = s.db.Exec(`DELETE FROM join_tokens WHERE expires_at<?`, s.now().Add(-24*time.Hour).Unix())
	return ids, nil
}

// PurgeTombstones drops tombstones older than cutoff and frees their rows.
func (s *Store) PurgeTombstones(cutoff time.Time) (int64, error) {
	var removed int64
	err := s.tx(func(t *sql.Tx) error {
		if _, err := t.Exec(`UPDATE groups SET rows = rows - (SELECT COUNT(*) FROM docs d WHERE d.group_id=groups.id AND d.deleted=1 AND d.updated_at<?)`, cutoff.Unix()); err != nil {
			return err
		}
		res, err := t.Exec(`DELETE FROM docs WHERE deleted=1 AND updated_at<?`, cutoff.Unix())
		if err != nil {
			return err
		}
		removed, _ = res.RowsAffected()
		return nil
	})
	return removed, err
}

// ---------- documents ----------

type Doc struct {
	Collection string
	DocID      string
	Seq        int64
	Env        []byte
	Size       int64
	Deleted    bool
	UpdatedAt  int64
}

// PutDoc writes env if the stored seq matches ifMatch (0 = must not exist).
// On conflict it returns ErrConflict and the current seq.
func (s *Store) PutDoc(gid, coll, docID string, env []byte, ifMatch int64, q Quota) (int64, int64, error) {
	var newSeq, cur int64
	err := s.tx(func(t *sql.Tx) error {
		var curSeq, size int64
		var deleted int
		err := t.QueryRow(`SELECT seq,size,deleted FROM docs WHERE group_id=? AND collection=? AND doc_id=?`, gid, coll, docID).Scan(&curSeq, &size, &deleted)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if (exists && curSeq != ifMatch) || (!exists && ifMatch != 0) {
			cur = curSeq
			return ErrConflict
		}
		var docs, rows int
		var bytes int64
		if err := t.QueryRow(`SELECT docs,rows,bytes FROM groups WHERE id=?`, gid).Scan(&docs, &rows, &bytes); err != nil {
			return ErrNotFound
		}
		addDocs, addRows, addBytes := 0, 0, int64(len(env))
		if !exists {
			addDocs, addRows = 1, 1
		} else {
			addBytes -= size
			if deleted == 1 {
				addDocs = 1
			}
		}
		if docs+addDocs > q.MaxDocs || rows+addRows > q.MaxRows || bytes+addBytes > q.MaxBytes {
			return ErrQuota
		}
		n := s.now()
		if _, err := t.Exec(`UPDATE groups SET seq=seq+1,docs=docs+?,rows=rows+?,bytes=bytes+?,last_activity=? WHERE id=?`, addDocs, addRows, addBytes, n.Unix(), gid); err != nil {
			return err
		}
		if err := t.QueryRow(`SELECT seq FROM groups WHERE id=?`, gid).Scan(&newSeq); err != nil {
			return err
		}
		_, err = t.Exec(`INSERT INTO docs(group_id,collection,doc_id,seq,env,size,deleted,updated_at) VALUES(?,?,?,?,?,?,0,?)
ON CONFLICT(group_id,collection,doc_id) DO UPDATE SET seq=excluded.seq,env=excluded.env,size=excluded.size,deleted=0,updated_at=excluded.updated_at`,
			gid, coll, docID, newSeq, env, len(env), n.Unix())
		return err
	})
	return newSeq, cur, err
}

func (s *Store) GetDoc(gid, coll, docID string) (Doc, error) {
	d := Doc{Collection: coll, DocID: docID}
	var del int
	err := s.db.QueryRow(`SELECT seq,env,deleted,updated_at FROM docs WHERE group_id=? AND collection=? AND doc_id=?`, gid, coll, docID).
		Scan(&d.Seq, &d.Env, &del, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	d.Deleted = del == 1
	return d, err
}

// DeleteDoc turns the document into a tombstone (content erased, seq bumped).
func (s *Store) DeleteDoc(gid, coll, docID string, ifMatch int64) (int64, int64, error) {
	var newSeq, cur int64
	err := s.tx(func(t *sql.Tx) error {
		var curSeq, size int64
		var del int
		err := t.QueryRow(`SELECT seq,size,deleted FROM docs WHERE group_id=? AND collection=? AND doc_id=?`, gid, coll, docID).Scan(&curSeq, &size, &del)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if curSeq != ifMatch {
			cur = curSeq
			return ErrConflict
		}
		freed := 0
		if del == 0 {
			freed = 1
		}
		n := s.now().Unix()
		if _, err := t.Exec(`UPDATE groups SET seq=seq+1,docs=docs-?,bytes=bytes-?,last_activity=? WHERE id=?`, freed, size, n, gid); err != nil {
			return err
		}
		if err := t.QueryRow(`SELECT seq FROM groups WHERE id=?`, gid).Scan(&newSeq); err != nil {
			return err
		}
		_, err = t.Exec(`UPDATE docs SET seq=?,env=NULL,size=0,deleted=1,updated_at=? WHERE group_id=? AND collection=? AND doc_id=?`, newSeq, n, gid, coll, docID)
		return err
	})
	return newSeq, cur, err
}

// Changes returns documents with seq > since, in seq order, stopping once the
// cumulative envelope size reaches maxBytes (at least one item is returned).
func (s *Store) Changes(gid string, since int64, limit int, maxBytes int64) (items []Doc, more bool, err error) {
	rows, err := s.db.Query(`SELECT collection,doc_id,seq,env,size,deleted,updated_at FROM docs WHERE group_id=? AND seq>? ORDER BY seq LIMIT ?`, gid, since, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var total int64
	for rows.Next() {
		var d Doc
		var del int
		if err := rows.Scan(&d.Collection, &d.DocID, &d.Seq, &d.Env, &d.Size, &del, &d.UpdatedAt); err != nil {
			return nil, false, err
		}
		d.Deleted = del == 1
		if len(items) > 0 && (len(items) >= limit || total+d.Size > maxBytes) {
			return items, true, rows.Err()
		}
		total += d.Size
		items = append(items, d)
	}
	return items, false, rows.Err()
}

// ChangesMeta is Changes without the envelope column (used by SSE wake-ups).
func (s *Store) ChangesMeta(gid string, since int64, limit int) (items []Doc, more bool, err error) {
	rows, err := s.db.Query(`SELECT collection,doc_id,seq,size,deleted,updated_at FROM docs WHERE group_id=? AND seq>? ORDER BY seq LIMIT ?`, gid, since, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var d Doc
		var del int
		if err := rows.Scan(&d.Collection, &d.DocID, &d.Seq, &d.Size, &del, &d.UpdatedAt); err != nil {
			return nil, false, err
		}
		d.Deleted = del == 1
		items = append(items, d)
	}
	if len(items) > limit {
		items, more = items[:limit], true
	}
	return items, more, rows.Err()
}

// ---------- blobs ----------

// File names never reuse client-supplied text: case-insensitive filesystems and
// odd characters cannot make two blobs collide or escape the directory.
func (s *Store) blobGroupDir(gid string) string {
	h := sha256.Sum256([]byte(gid))
	return filepath.Join(s.blobDir, hex.EncodeToString(h[:16]))
}

func (s *Store) blobPath(gid, id string) string {
	h := sha256.Sum256([]byte(id))
	return filepath.Join(s.blobGroupDir(gid), hex.EncodeToString(h[:16]))
}

func blobCost(size, min int64) int64 {
	if size < min {
		return min
	}
	return size
}

// PutBlob stores a blob atomically (temp file + rename) while holding the blob
// lock, so accounting and the file on disk can never diverge.
func (s *Store) PutBlob(gid, id string, data []byte, q Quota) error {
	if int64(len(data)) > q.MaxBlobSize {
		return ErrTooLarge
	}
	s.blobMu.Lock()
	defer s.blobMu.Unlock()
	final := s.blobPath(gid, id)
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return err
	}
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := final + ".tmp-" + hex.EncodeToString(rnd[:])
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	cost := blobCost(int64(len(data)), q.BlobMinCost)
	err = s.tx(func(t *sql.Tx) error {
		var oldCost int64
		exists := t.QueryRow(`SELECT cost FROM blobs WHERE group_id=? AND blob_id=?`, gid, id).Scan(&oldCost) == nil
		var bytes int64
		if err := t.QueryRow(`SELECT bytes FROM groups WHERE id=?`, gid).Scan(&bytes); err != nil {
			return ErrNotFound
		}
		if !exists {
			var n int
			if err := t.QueryRow(`SELECT COUNT(*) FROM blobs WHERE group_id=?`, gid).Scan(&n); err != nil {
				return err
			}
			if n >= q.MaxBlobs {
				return ErrQuota
			}
		}
		if bytes-oldCost+cost > q.MaxBytes {
			return ErrQuota
		}
		now := s.now().Unix()
		if _, err := t.Exec(`UPDATE groups SET bytes=bytes-?+?,last_activity=? WHERE id=?`, oldCost, cost, now, gid); err != nil {
			return err
		}
		if _, err := t.Exec(`INSERT INTO blobs(group_id,blob_id,size,cost,updated_at) VALUES(?,?,?,?,?)
ON CONFLICT(group_id,blob_id) DO UPDATE SET size=excluded.size,cost=excluded.cost,updated_at=excluded.updated_at`, gid, id, len(data), cost, now); err != nil {
			return err
		}
		return os.Rename(tmp, final) // inside the transaction: failure rolls the rows back
	})
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// OpenBlob returns the blob file; callers close it.
func (s *Store) OpenBlob(gid, id string) (*os.File, os.FileInfo, error) {
	f, err := os.Open(s.blobPath(gid, id))
	if err != nil {
		return nil, nil, ErrNotFound
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, st, nil
}

func (s *Store) DeleteBlob(gid, id string) error {
	s.blobMu.Lock()
	defer s.blobMu.Unlock()
	err := s.tx(func(t *sql.Tx) error {
		var cost int64
		if err := t.QueryRow(`SELECT cost FROM blobs WHERE group_id=? AND blob_id=?`, gid, id).Scan(&cost); err != nil {
			return ErrNotFound
		}
		if _, err := t.Exec(`DELETE FROM blobs WHERE group_id=? AND blob_id=?`, gid, id); err != nil {
			return err
		}
		_, err := t.Exec(`UPDATE groups SET bytes=bytes-? WHERE id=?`, cost, gid)
		return err
	})
	if err == nil {
		_ = os.Remove(s.blobPath(gid, id))
	}
	return err
}

// ---------- public ratings ----------

// PutRating upserts a vote stamped ts (seconds); r == nil removes it. A vote
// whose ts is not strictly newer than the stored one is refused (ErrStale),
// which also defeats replay of an old captured vote.
func (s *Store) PutRating(key, pseudonym string, r *float64, ts int64, maxRows int) error {
	return s.tx(func(t *sql.Tx) error {
		var old int64
		err := t.QueryRow(`SELECT ts FROM ratings WHERE content_key=? AND pseudonym=?`, key, pseudonym).Scan(&old)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if exists && ts <= old {
			return ErrStale
		}
		if !exists {
			var n int
			if err := t.QueryRow(`SELECT COUNT(*) FROM ratings`).Scan(&n); err != nil {
				return err
			}
			if n >= maxRows {
				return ErrFull
			}
		}
		del := 0
		var v any = nil
		if r == nil {
			del = 1
		} else {
			v = *r
		}
		_, err = t.Exec(`INSERT INTO ratings(content_key,pseudonym,rating,ts,deleted) VALUES(?,?,?,?,?)
ON CONFLICT(content_key,pseudonym) DO UPDATE SET rating=excluded.rating,ts=excluded.ts,deleted=excluded.deleted`, key, pseudonym, v, ts, del)
		return err
	})
}

type Aggregate struct {
	Count int     `json:"count"`
	Sum   float64 `json:"sum"`
	Avg   float64 `json:"avg"`
}

func (s *Store) Aggregates(keys []string) (map[string]Aggregate, error) {
	out := make(map[string]Aggregate, len(keys))
	for _, k := range keys {
		var a Aggregate
		var sum sql.NullFloat64
		if err := s.db.QueryRow(`SELECT COUNT(*),SUM(rating) FROM ratings WHERE content_key=? AND deleted=0`, k).Scan(&a.Count, &sum); err != nil {
			return nil, err
		}
		a.Sum = sum.Float64
		if a.Count > 0 {
			a.Avg = a.Sum / float64(a.Count)
		}
		out[k] = a
	}
	return out, nil
}

// Totals feeds the metrics endpoint.
func (s *Store) Totals() (groups, docs int, bytes int64, ratings int, err error) {
	err = s.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(docs),0),COALESCE(SUM(bytes),0) FROM groups`).Scan(&groups, &docs, &bytes)
	if err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT COUNT(*) FROM ratings WHERE deleted=0`).Scan(&ratings)
	return
}
