package manifest

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// DB 是公网接管清单：SQLite 持久接收顺序与接管状态。
// DB is the public takeover manifest: receive order and takeover state.
type DB struct {
	db *sql.DB
}

// Record 是一行清单记录。Record is one manifest row.
type Record struct {
	// Sequence 是服务端持久接收顺序（AUTOINCREMENT，不代表客户端修改顺序）。Server receive order.
	Sequence int64
	// ArchiveID 是归档编号。Archive ID.
	ArchiveID string
	// ReceivedAt 是固定接收时间（UTC RFC3339）。Fixed receive time.
	ReceivedAt string
	// PubkeyHex 是提交者公钥小写 hex。Submitter public key hex.
	PubkeyHex string
	// DigestHex 是签名摘要小写 hex。Signature digest hex.
	DigestHex string
	// Bytes 是 gzip 字节数。Gzip byte length.
	Bytes int64
	// State 是待接管、已接管、已清理。Takeover state.
	State string
	// AcknowledgedAt 是内网确认接管时间（可空）。Ack time, nullable.
	AcknowledgedAt sql.NullString
	// GzipPath 是归档文件绝对路径。Absolute gzip path.
	GzipPath string
	// SigPath 是签名文件绝对路径。Absolute sig path.
	SigPath string
}

// Open 打开（不存在则创建）清单库并建表。
// Open opens the manifest database and creates the schema.
func Open(path string) (*DB, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("manifest: path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("manifest: open: %w", err)
	}
	pragmas := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA synchronous=FULL`,
		`PRAGMA busy_timeout=5000`,
		`PRAGMA foreign_keys=ON`,
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("manifest: %s: %w", p, err)
		}
	}
	schema := `
CREATE TABLE IF NOT EXISTS archives (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  archive_id TEXT NOT NULL UNIQUE,
  received_at TEXT NOT NULL,
  pubkey_hex TEXT NOT NULL,
  digest_hex TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  state TEXT NOT NULL,
  acknowledged_at TEXT,
  gzip_path TEXT NOT NULL,
  sig_path TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_archives_state_seq ON archives(state, sequence);
`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("manifest: schema: %w", err)
	}
	return &DB{db: db}, nil
}

// Close 关闭清单库。Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

// InsertPending 插入一条待接管记录，返回分配的 sequence。
// InsertPending inserts a pending row and returns its sequence.
func (d *DB) InsertPending(archiveID, receivedAt, pubkeyHex, digestHex string, size int64, gzipPath, sigPath string) (int64, error) {
	res, err := d.db.Exec(
		`INSERT INTO archives(archive_id, received_at, pubkey_hex, digest_hex, bytes, state, gzip_path, sig_path)
		 VALUES(?, ?, ?, ?, ?, 'pending', ?, ?)`,
		archiveID, receivedAt, pubkeyHex, digestHex, size, gzipPath, sigPath,
	)
	if err != nil {
		return 0, fmt.Errorf("manifest: insert: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("manifest: last insert id: %w", err)
	}
	return seq, nil
}

// InsertPendingIgnore 插入待接管记录，已存在则返回既有 sequence 与 repeated=true（恢复用）。
// InsertPendingIgnore inserts or returns the existing row for crash recovery.
func (d *DB) InsertPendingIgnore(archiveID, receivedAt, pubkeyHex, digestHex string, size int64, gzipPath, sigPath string) (seq int64, repeated bool, err error) {
	res, err := d.db.Exec(
		`INSERT OR IGNORE INTO archives(archive_id, received_at, pubkey_hex, digest_hex, bytes, state, gzip_path, sig_path)
		 VALUES(?, ?, ?, ?, ?, 'pending', ?, ?)`,
		archiveID, receivedAt, pubkeyHex, digestHex, size, gzipPath, sigPath,
	)
	if err != nil {
		return 0, false, fmt.Errorf("manifest: insert ignore: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, false, fmt.Errorf("manifest: rows affected: %w", err)
	}
	if n == 1 {
		seq, err := res.LastInsertId()
		if err != nil {
			return 0, false, fmt.Errorf("manifest: last insert id: %w", err)
		}
		return seq, false, nil
	}
	rec, err := d.Get(archiveID)
	if err != nil {
		return 0, false, err
	}
	return rec.Sequence, true, nil
}

// Get 按归档编号取记录。Get fetches one row by archive ID.
func (d *DB) Get(archiveID string) (*Record, error) {
	row := d.db.QueryRow(
		`SELECT sequence, archive_id, received_at, pubkey_hex, digest_hex, bytes, state, acknowledged_at, gzip_path, sig_path
		 FROM archives WHERE archive_id = ?`, archiveID,
	)
	var r Record
	if err := row.Scan(&r.Sequence, &r.ArchiveID, &r.ReceivedAt, &r.PubkeyHex, &r.DigestHex, &r.Bytes, &r.State, &r.AcknowledgedAt, &r.GzipPath, &r.SigPath); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("manifest: archive %s: not found", archiveID)
		}
		return nil, fmt.Errorf("manifest: get: %w", err)
	}
	return &r, nil
}

// ListPending 按 sequence 升序列出待接管记录。
// ListPending lists pending rows in ascending sequence order.
func (d *DB) ListPending(after int64, limit int) ([]Record, error) {
	rows, err := d.db.Query(
		`SELECT sequence, archive_id, received_at, pubkey_hex, digest_hex, bytes, state, acknowledged_at, gzip_path, sig_path
		 FROM archives WHERE state = 'pending' AND sequence > ? ORDER BY sequence ASC LIMIT ?`, after, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("manifest: list: %w", err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.Sequence, &r.ArchiveID, &r.ReceivedAt, &r.PubkeyHex, &r.DigestHex, &r.Bytes, &r.State, &r.AcknowledgedAt, &r.GzipPath, &r.SigPath); err != nil {
			return nil, fmt.Errorf("manifest: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("manifest: rows: %w", err)
	}
	return out, nil
}

// MarkAcknowledged 将记录置为已接管；已接管或已清理时返回 repeated=true。
// MarkAcknowledged marks a row acknowledged; repeats report repeated=true.
func (d *DB) MarkAcknowledged(archiveID, at string) (repeated bool, err error) {
	res, err := d.db.Exec(
		`UPDATE archives SET state = 'acknowledged', acknowledged_at = ? WHERE archive_id = ? AND state = 'pending'`,
		at, archiveID,
	)
	if err != nil {
		return false, fmt.Errorf("manifest: ack: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("manifest: rows affected: %w", err)
	}
	if n == 1 {
		return false, nil
	}
	rec, err := d.Get(archiveID)
	if err != nil {
		return false, err
	}
	if rec.State == "acknowledged" || rec.State == "cleaned" {
		return true, nil
	}
	return false, fmt.Errorf("manifest: archive %s: unexpected state %s", archiveID, rec.State)
}

// MarkCleaned 将记录置为已清理。MarkCleaned marks a row cleaned.
func (d *DB) MarkCleaned(archiveID string) error {
	res, err := d.db.Exec(
		`UPDATE archives SET state = 'cleaned' WHERE archive_id = ? AND state = 'acknowledged'`,
		archiveID,
	)
	if err != nil {
		return fmt.Errorf("manifest: clean: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("manifest: rows affected: %w", err)
	}
	if n != 1 {
		rec, err := d.Get(archiveID)
		if err != nil {
			return err
		}
		if rec.State == "cleaned" {
			return nil
		}
		return fmt.Errorf("manifest: archive %s: unexpected state %s", archiveID, rec.State)
	}
	return nil
}

// ListByState 按状态列出记录（清理补偿用）。
// ListByState lists rows by state for cleanup compensation.
func (d *DB) ListByState(state string) ([]Record, error) {
	rows, err := d.db.Query(
		`SELECT sequence, archive_id, received_at, pubkey_hex, digest_hex, bytes, state, acknowledged_at, gzip_path, sig_path
		 FROM archives WHERE state = ? ORDER BY sequence ASC`, state,
	)
	if err != nil {
		return nil, fmt.Errorf("manifest: list by state: %w", err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.Sequence, &r.ArchiveID, &r.ReceivedAt, &r.PubkeyHex, &r.DigestHex, &r.Bytes, &r.State, &r.AcknowledgedAt, &r.GzipPath, &r.SigPath); err != nil {
			return nil, fmt.Errorf("manifest: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("manifest: rows: %w", err)
	}
	return out, nil
}
