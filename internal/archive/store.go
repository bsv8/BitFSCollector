package archive

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bsv8/BitFSCollector/internal/disk"
	"github.com/bsv8/BitFSCollector/internal/manifest"
	collector "github.com/bsv8/BitFSCollectorProtocol/collector"
)

// Store 是归档存储：验签通过后将 gzip 与 .sig 原样持久化，并在清单记一笔待接管。
// Store verifies submissions, persists the exact bytes and manifests them.
type Store struct {
	// Root 是归档根目录。Root is the archive root directory.
	Root string
	// MaxBodyBytes 是请求体上限。MaxBodyBytes caps the request body.
	MaxBodyBytes int64
	// MinFreeBytes 是磁盘可用下限，低于则拒绝新提交。Free-space floor.
	MinFreeBytes int64
	// Manifest 是接管清单。Manifest tracks pending takeovers.
	Manifest *manifest.DB
	// Now 由调用方注入时钟，便于测试。Now is an injected clock for tests.
	Now func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Store) maxBody() int64 {
	if s.MaxBodyBytes > 0 {
		return s.MaxBodyBytes
	}
	return 32 << 20
}

func (s *Store) minFree() int64 {
	if s.MinFreeBytes > 0 {
		return s.MinFreeBytes
	}
	return 1 << 30
}

// Result 是成功归档的结果。Result describes a successful archive.
type Result struct {
	ArchiveID string
	Sequence  int64
	PubkeyHex string
	DigestHex string
	Bytes     int64
}

// Handle 实现 POST /v1/submissions：流式收字节→验签→落盘→记清单→回执。
// Handle serves one submission: stream, verify, persist, manifest, receipt.
func (s *Store) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, collector.CodeMalformedRequest, "not found")
		return
	}
	if free, err := disk.FreeBytes(s.Root); err == nil && int64(free) < s.minFree() {
		writeError(w, http.StatusTooManyRequests, collector.CodeRateLimited, "disk low, retry later")
		return
	}
	pubkeyHex := strings.ToLower(strings.TrimSpace(r.Header.Get(collector.HeaderPubkey)))
	sigHex := strings.ToLower(strings.TrimSpace(r.Header.Get(collector.HeaderSignature)))
	sigVersion := strings.TrimSpace(r.Header.Get(collector.HeaderSigVersion))
	pubkey, err := collector.ParsePublicKeyHex(pubkeyHex)
	if err != nil || sigVersion != fmt.Sprint(collector.SigVersion) {
		// 头非法时仍需排空 body 以复用连接，但不落盘。
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		writeError(w, http.StatusBadRequest, collector.CodeMalformedRequest, "bad headers")
		return
	}
	sigRaw, err := hex.DecodeString(sigHex)
	if err != nil || len(sigRaw) == 0 {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		writeError(w, http.StatusBadRequest, collector.CodeMalformedRequest, "bad signature encoding")
		return
	}
	now := s.now()
	dir := filepath.Join(s.Root,
		fmt.Sprintf("%04d", now.Year()),
		fmt.Sprintf("%02d", int(now.Month())),
		fmt.Sprintf("%02d", now.Day()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "persist failed")
		return
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "persist failed")
		return
	}
	archiveID := hex.EncodeToString(id)
	base := pubkeyHex + "-" + archiveID
	tmpGzip := filepath.Join(dir, base+".gzip.tmp")
	// 边收边写临时文件并计算摘要：内存占用恒定。
	limit := s.maxBody()
	f, err := os.OpenFile(tmpGzip, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "persist failed")
		return
	}
	h := sha256.New()
	h.Write([]byte(collector.SignatureDomain))
	n, copyErr := io.Copy(f, io.TeeReader(io.LimitReader(r.Body, limit+1), h))
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmpGzip)
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "read failed")
		return
	}
	if n > limit {
		_ = os.Remove(tmpGzip)
		writeError(w, http.StatusRequestEntityTooLarge, collector.CodeMalformedRequest, "body too large")
		return
	}
	if n == 0 {
		_ = os.Remove(tmpGzip)
		writeError(w, http.StatusBadRequest, collector.CodeMalformedRequest, "empty body")
		return
	}
	var digest collector.Digest32
	copy(digest[:], h.Sum(nil))
	if err := collector.VerifyDigestSignature(pubkey, digest, sigRaw); err != nil {
		_ = os.Remove(tmpGzip)
		writeError(w, http.StatusUnauthorized, collector.CodeUnauthorized, "signature invalid")
		return
	}
	sigFile, err := collector.EncodeSigFile(digest, pubkey, sigRaw)
	if err != nil {
		_ = os.Remove(tmpGzip)
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "sig envelope failed")
		return
	}
	res, err := s.publish(now, dir, base, archiveID, pubkeyHex, digest, n, tmpGzip, sigFile)
	if err != nil {
		_ = os.Remove(tmpGzip)
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "persist failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"version":1,"archiveId":%q,"receivedAt":%q,"pubkeyHex":%q,"digestHex":%q,"bytes":%q}`,
		res.ArchiveID, now.Format(time.RFC3339), res.PubkeyHex, res.DigestHex, fmt.Sprint(res.Bytes))
}

// publish 落盘签名文件、原子发布两个文件、记清单；失败时调用方清理。
// publish persists the sig file, publishes both files and manifests the row.
func (s *Store) publish(now time.Time, dir, base, archiveID, pubkeyHex string, digest collector.Digest32, size int64, tmpGzip string, sigFile []byte) (*Result, error) {
	tmpSig := filepath.Join(dir, base+".sig.tmp")
	finalGzip := filepath.Join(dir, base+".gzip")
	finalSig := filepath.Join(dir, base+".sig")
	cleanup := func() {
		_ = os.Remove(tmpGzip)
		_ = os.Remove(tmpSig)
	}
	if err := writeSync(tmpSig, sigFile); err != nil {
		cleanup()
		return nil, err
	}
	// O_EXCL 语义：目标已存在即失败，绝不覆盖。
	if err := linkOrFail(tmpGzip, finalGzip); err != nil {
		cleanup()
		return nil, err
	}
	if err := linkOrFail(tmpSig, finalSig); err != nil {
		_ = os.Remove(finalGzip)
		cleanup()
		return nil, err
	}
	if err := syncDir(dir); err != nil {
		cleanup()
		return nil, err
	}
	digestHex := fmt.Sprintf("%x", digest)
	receivedAt := now.Format(time.RFC3339)
	if s.Manifest != nil {
		seq, err := s.Manifest.InsertPending(archiveID, receivedAt, pubkeyHex, digestHex, size, finalGzip, finalSig)
		if err != nil {
			_ = os.Remove(finalGzip)
			_ = os.Remove(finalSig)
			return nil, err
		}
		return &Result{ArchiveID: archiveID, Sequence: seq, PubkeyHex: pubkeyHex, DigestHex: digestHex, Bytes: size}, nil
	}
	return &Result{ArchiveID: archiveID, PubkeyHex: pubkeyHex, DigestHex: digestHex, Bytes: size}, nil
}

// linkOrFail 以硬链接实现 O_EXCL 改名：目标已存在即失败，绝不覆盖。
// linkOrFail renames via hard link so an existing target fails, never overwrites.
func linkOrFail(tmp, final string) error {
	if err := os.Link(tmp, final); err != nil {
		return err
	}
	return os.Remove(tmp)
}

func writeSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func writeError(w http.ResponseWriter, status int, code collector.ErrorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"code":%q,"message":%q}`, string(code), message)
}
