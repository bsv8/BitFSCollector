package archive

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/BitFSCollector/internal/auth"
	"github.com/bsv8/BitFSCollector/internal/manifest"
	collector "github.com/bsv8/BitFSCollectorProtocol/collector"
)

var testRecords = []collector.FileRecord{
	{SeedHashHex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", FileName: "example.pdf", Description: "", FileSizeBytes: "123456", MediaType: "application/pdf"},
	{SeedHashHex: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", FileName: "notes.txt", Description: "lorem ipsum", FileSizeBytes: "42", MediaType: "text/plain"},
}

func testSigner(t *testing.T) (*collector.PrivateKeySigner, collector.PublicKey) {
	t.Helper()
	key, _ := ec.PrivateKeyFromBytes(bytes.Repeat([]byte{0x22}, 32))
	signer, err := collector.NewPrivateKeySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer, signer.PublicKey()
}

func newTestManifest(t *testing.T, dir string) *manifest.DB {
	t.Helper()
	db, err := manifest.Open(filepath.Join(dir, "manifest.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func submit(t *testing.T, url string, gzipBytes, sig []byte, pub collector.PublicKey) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+collector.SubmissionsPath, bytes.NewReader(gzipBytes))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", collector.ContentType)
	req.Header.Set(collector.HeaderPubkey, hex.EncodeToString(pub[:]))
	req.Header.Set(collector.HeaderSignature, hex.EncodeToString(sig))
	req.Header.Set(collector.HeaderSigVersion, "1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body
}

func buildSubmission(t *testing.T) (gzipBytes, sig []byte, pub collector.PublicKey) {
	t.Helper()
	canonical, err := collector.EncodeSubmission(testRecords)
	if err != nil {
		t.Fatal(err)
	}
	gzipBytes, err = collector.GzipJSON(canonical)
	if err != nil {
		t.Fatal(err)
	}
	signer, pub := testSigner(t)
	sig, _, err = collector.SignGzip(context.Background(), signer, gzipBytes)
	if err != nil {
		t.Fatal(err)
	}
	return gzipBytes, sig, pub
}

func TestArchiveLayoutAndBytes(t *testing.T) {
	root := t.TempDir()
	fixed := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	db := newTestManifest(t, t.TempDir())
	store := &Store{Root: root, MaxBodyBytes: 32 << 20, Manifest: db, Now: func() time.Time { return fixed }}
	server := httptest.NewServer(http.HandlerFunc(store.Handle))
	defer server.Close()
	gzipBytes, sig, pub := buildSubmission(t)
	status, body := submit(t, server.URL, gzipBytes, sig, pub)
	if status != http.StatusOK {
		t.Fatalf("status %d body %v", status, body)
	}
	archiveID, _ := body["archiveId"].(string)
	if archiveID == "" {
		t.Fatalf("missing archiveId %v", body)
	}
	pubHex := hex.EncodeToString(pub[:])
	dir := filepath.Join(root, "2026", "11", "07")
	gzipPath := filepath.Join(dir, pubHex+"-"+archiveID+".gzip")
	sigPath := filepath.Join(dir, pubHex+"-"+archiveID+".sig")
	got, err := os.ReadFile(gzipPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, gzipBytes) {
		t.Fatal("archived gzip differs from request bytes")
	}
	sigRaw, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(sigRaw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["sigVersion"] != 1.0 || doc["pubkeyHex"] != pubHex || doc["signatureHex"] != hex.EncodeToString(sig) {
		t.Fatalf("bad .sig envelope %v", doc)
	}
	if body["digestHex"] != doc["digestHex"] || body["pubkeyHex"] != pubHex {
		t.Fatalf("receipt mismatch %v", body)
	}
	// 清单应有一笔待接管。
	rec, err := db.Get(archiveID)
	if err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	if rec.State != "pending" || rec.Sequence != 1 || rec.GzipPath != gzipPath {
		t.Fatalf("bad manifest row %+v", rec)
	}
	// 第二次提交产生不同编号，不覆盖。
	status2, body2 := submit(t, server.URL, gzipBytes, sig, pub)
	if status2 != http.StatusOK {
		t.Fatalf("second submit status %d", status2)
	}
	if body2["archiveId"] == archiveID {
		t.Fatal("archive id reused across submissions")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 files, got %d", len(entries))
	}
	// Go SDK 客户端同样能走通，完整 URL（含路径）亦可。
	receipt, err := collector.Submit(context.Background(), server.Client(), server.URL, gzipBytes, sig, pub)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArchiveID == "" {
		t.Fatalf("bad receipt %+v", receipt)
	}
	receipt, err = collector.Submit(context.Background(), server.Client(), server.URL+collector.SubmissionsPath, gzipBytes, sig, pub)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArchiveID == "" {
		t.Fatalf("bad receipt %+v", receipt)
	}
}

func TestTamperedBodyRejected(t *testing.T) {
	root := t.TempDir()
	db := newTestManifest(t, t.TempDir())
	store := &Store{Root: root, MaxBodyBytes: 32 << 20, Manifest: db}
	server := httptest.NewServer(http.HandlerFunc(store.Handle))
	defer server.Close()
	gzipBytes, sig, pub := buildSubmission(t)
	evil := append([]byte(nil), gzipBytes...)
	evil[len(evil)/2] ^= 0x01
	status, _ := submit(t, server.URL, evil, sig, pub)
	if status != http.StatusUnauthorized {
		t.Fatalf("tampered bytes must be 401, got %d", status)
	}
	var count int
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && !strings.HasSuffix(path, ".tmp") {
			count++
		}
		return nil
	})
	if count != 0 {
		t.Fatalf("rejected submission entered archive (%d files)", count)
	}
	rows, err := db.ListPending(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("rejected submission entered manifest (%d rows)", len(rows))
	}
}

func TestWriteFailureNotSuccess(t *testing.T) {
	// 归档根是普通文件：建目录必败，服务端不得返回成功。
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	db := newTestManifest(t, t.TempDir())
	store := &Store{Root: blocker, MaxBodyBytes: 32 << 20, Manifest: db}
	server := httptest.NewServer(http.HandlerFunc(store.Handle))
	defer server.Close()
	gzipBytes, sig, pub := buildSubmission(t)
	status, body := submit(t, server.URL, gzipBytes, sig, pub)
	if status != http.StatusInternalServerError {
		t.Fatalf("write failure must be 500, got %d %v", status, body)
	}
	if body["code"] != "storage_failed" {
		t.Fatalf("expected storage_failed, got %v", body)
	}
}

func TestBodyTooLarge(t *testing.T) {
	root := t.TempDir()
	db := newTestManifest(t, t.TempDir())
	store := &Store{Root: root, MaxBodyBytes: 16, Manifest: db}
	server := httptest.NewServer(http.HandlerFunc(store.Handle))
	defer server.Close()
	gzipBytes, sig, pub := buildSubmission(t)
	status, _ := submit(t, server.URL, gzipBytes, sig, pub)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize must be 413, got %d", status)
	}
	rows, err := db.ListPending(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatal("oversize body entered manifest")
	}
}

func TestV2ListDownloadAck(t *testing.T) {
	root := t.TempDir()
	fixed := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	db := newTestManifest(t, t.TempDir())
	store := &Store{Root: root, MaxBodyBytes: 32 << 20, Manifest: db, Now: func() time.Time { return fixed }}
	v2 := &V2{Manifest: db, Auth: auth.New([]string{"pull-secret"}), MaxDownloadBytes: 32 << 20}
	mux := http.NewServeMux()
	mux.HandleFunc(collector.SubmissionsPath, store.Handle)
	mux.HandleFunc(collector.ArchivesPath, v2.HandleList)
	mux.HandleFunc(collector.ArchivesPath+"/", v2.HandleArtifact)
	server := httptest.NewServer(mux)
	defer server.Close()
	gzipBytes, sig, pub := buildSubmission(t)
	if status, _ := submit(t, server.URL, gzipBytes, sig, pub); status != http.StatusOK {
		t.Fatalf("submit status %d", status)
	}
	pull := &collector.PullClient{BaseURL: server.URL, Token: "pull-secret", Client: server.Client()}
	list, err := pull.List(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Archives) != 1 || list.NextAfter != 1 {
		t.Fatalf("unexpected list %+v", list)
	}
	id := list.Archives[0].ArchiveID
	got, err := pull.FetchGzip(context.Background(), id)
	if err != nil || !bytes.Equal(got, gzipBytes) {
		t.Fatalf("gzip mismatch: %v", err)
	}
	sigDoc, err := pull.FetchSig(context.Background(), id)
	if err != nil || len(sigDoc) == 0 {
		t.Fatalf("sig fetch failed: %v", err)
	}
	ack, err := pull.Ack(context.Background(), id)
	if err != nil || ack.Repeated {
		t.Fatalf("first ack must not be repeated: %+v %v", ack, err)
	}
	// ack 后文件删除、清单记清理、清单不再列出。
	rec, err := db.Get(id)
	if err != nil || rec.State != "cleaned" {
		t.Fatalf("expected cleaned, got %+v %v", rec, err)
	}
	if _, err := os.Stat(rec.GzipPath); !os.IsNotExist(err) {
		t.Fatal("gzip not deleted after ack")
	}
	list2, err := pull.List(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(list2.Archives) != 0 {
		t.Fatalf("cleaned archive still listed: %+v", list2)
	}
	// 重复确认成功。
	ack2, err := pull.Ack(context.Background(), id)
	if err != nil || !ack2.Repeated {
		t.Fatalf("repeat ack must succeed repeated: %+v %v", ack2, err)
	}
	// 无 Bearer 拒绝。
	anon := &collector.PullClient{BaseURL: server.URL, Token: "wrong", Client: server.Client()}
	if _, err := anon.List(context.Background(), 0, 10); !collector.IsCode(err, collector.CodeUnauthorized) {
		t.Fatalf("bad bearer must be unauthorized, got %v", err)
	}
}

func TestRecoverRelistsCompletePair(t *testing.T) {
	root := t.TempDir()
	db := newTestManifest(t, t.TempDir())
	fixed := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	store := &Store{Root: root, MaxBodyBytes: 32 << 20, Manifest: db, Now: func() time.Time { return fixed }}
	server := httptest.NewServer(http.HandlerFunc(store.Handle))
	gzipBytes, sig, pub := buildSubmission(t)
	if status, _ := submit(t, server.URL, gzipBytes, sig, pub); status != http.StatusOK {
		t.Fatal("submit failed")
	}
	server.Close()
	rows, err := db.ListPending(0, 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("expected 1 pending, got %+v %v", rows, err)
	}
	// 模拟崩溃：用空清单库对同一归档根恢复，完整文件对应重新记为待接管。
	db2, err := manifest.Open(filepath.Join(t.TempDir(), "manifest2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	// 留一个临时文件，恢复时应清理。
	_ = os.WriteFile(filepath.Join(root, "2026", "11", "07", "junk.gzip.tmp"), []byte("x"), 0o644)
	n, err := Recover(root, db2, 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 relisted, got %d", n)
	}
	rows2, err := db2.ListPending(0, 100)
	if err != nil || len(rows2) != 1 {
		t.Fatalf("expected 1 pending after recover, got %+v %v", rows2, err)
	}
	// 半份归档（缺 .sig）不进入清单。
	_ = os.Remove(rows2[0].SigPath)
	db3, err := manifest.Open(filepath.Join(t.TempDir(), "manifest3.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db3.Close()
	n, err = Recover(root, db3, 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("half archive must not relist, got %d", n)
	}
}
