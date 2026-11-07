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
	store := &Store{Root: root, MaxBodyBytes: 32 << 20, Now: func() time.Time { return fixed }}
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
	store := &Store{Root: root, MaxBodyBytes: 32 << 20}
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
}

func TestWriteFailureNotSuccess(t *testing.T) {
	// 归档根是普通文件：建目录必败，服务端不得返回成功。
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := &Store{Root: blocker, MaxBodyBytes: 32 << 20}
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
	store := &Store{Root: root, MaxBodyBytes: 16}
	server := httptest.NewServer(http.HandlerFunc(store.Handle))
	defer server.Close()
	gzipBytes, sig, pub := buildSubmission(t)
	status, _ := submit(t, server.URL, gzipBytes, sig, pub)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize must be 413, got %d", status)
	}
}
