package archive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bsv8/BitFSCollector/internal/auth"
	"github.com/bsv8/BitFSCollector/internal/manifest"
	collector "github.com/bsv8/BitFSCollectorProtocol/collector"
)

// TestRepeatAckRetriesFailedCleanup 删除失败时重复确认不得记清理，恢复后补删成功。
func TestRepeatAckRetriesFailedCleanup(t *testing.T) {
	root := t.TempDir()
	fixed := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	db, err := manifest.Open(filepath.Join(t.TempDir(), "manifest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &Store{Root: root, MaxBodyBytes: 32 << 20, Manifest: db, Now: func() time.Time { return fixed }}
	v2 := &V2{Manifest: db, Auth: auth.New([]string{"tok"}), MaxDownloadBytes: 32 << 20}
	mux := http.NewServeMux()
	mux.HandleFunc(collector.SubmissionsPath, store.Handle)
	mux.HandleFunc(collector.ArchivesPath, v2.HandleList)
	mux.HandleFunc(collector.ArchivesPath+"/", v2.HandleArtifact)
	server := httptest.NewServer(mux)
	defer server.Close()
	gzipBytes, sig, pub := buildSubmission(t)
	if status, _ := submit(t, server.URL, gzipBytes, sig, pub); status != http.StatusOK {
		t.Fatal("submit failed")
	}
	rows, err := db.ListPending(0, 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("expected 1 pending: %+v %v", rows, err)
	}
	id := rows[0].ArchiveID
	// 模拟确认已持久但进程在删除前崩溃。
	if _, err := db.MarkAcknowledged(id, fixed.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(rows[0].GzipPath)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	pull := &collector.PullClient{BaseURL: server.URL, Token: "tok", Client: server.Client()}
	if _, err := pull.Ack(context.Background(), id); !collector.IsCode(err, collector.CodeStorageFailed) {
		t.Fatalf("failed cleanup must be retryable storage_failed, got %v", err)
	}
	rec, err := db.Get(id)
	if err != nil || rec.State != "acknowledged" {
		t.Fatalf("must stay acknowledged: %+v %v", rec, err)
	}
	if _, err := os.Stat(rows[0].GzipPath); err != nil {
		t.Fatalf("file must remain: %v", err)
	}
	// 恢复写权限后重复确认补删成功。
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ack, err := pull.Ack(context.Background(), id)
	if err != nil || !ack.Repeated {
		t.Fatalf("repeat ack must succeed repeated: %+v %v", ack, err)
	}
	rec, err = db.Get(id)
	if err != nil || rec.State != "cleaned" {
		t.Fatalf("must be cleaned: %+v %v", rec, err)
	}
	if _, err := os.Stat(rows[0].GzipPath); !os.IsNotExist(err) {
		t.Fatal("file must be deleted")
	}
}

// TestRecoverCleanup 启动补偿已接管未清理的行。
func TestRecoverCleanup(t *testing.T) {
	root := t.TempDir()
	db, err := manifest.Open(filepath.Join(t.TempDir(), "manifest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &Store{Root: root, MaxBodyBytes: 32 << 20, Manifest: db}
	server := httptest.NewServer(http.HandlerFunc(store.Handle))
	defer server.Close()
	gzipBytes, sig, pub := buildSubmission(t)
	if status, _ := submit(t, server.URL, gzipBytes, sig, pub); status != http.StatusOK {
		t.Fatal("submit failed")
	}
	rows, err := db.ListPending(0, 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("expected 1 pending: %+v %v", rows, err)
	}
	if _, err := db.MarkAcknowledged(rows[0].ArchiveID, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	n, err := RecoverCleanup(db)
	if err != nil || n != 1 {
		t.Fatalf("expected 1 cleaned: %d %v", n, err)
	}
	rec, err := db.Get(rows[0].ArchiveID)
	if err != nil || rec.State != "cleaned" {
		t.Fatalf("must be cleaned: %+v %v", rec, err)
	}
	if _, err := os.Stat(rows[0].GzipPath); !os.IsNotExist(err) {
		t.Fatal("file must be deleted")
	}
	n, err = RecoverCleanup(db)
	if err != nil || n != 0 {
		t.Fatalf("second run must be idle: %d %v", n, err)
	}
}
