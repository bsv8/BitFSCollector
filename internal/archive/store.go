package archive

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	collector "github.com/bsv8/BitFSCollectorProtocol/collector"
)

// Store 是归档存储：验签通过后将 gzip 与 .sig 原样持久化。
// Store verifies submissions and persists the exact bytes.
type Store struct {
	// Root 是归档根目录。Root is the archive root directory.
	Root string
	// MaxBodyBytes 是请求体上限。MaxBodyBytes caps the request body.
	MaxBodyBytes int64
	// Now 由调用方注入时钟，便于测试。Now is an injected clock for tests.
	Now func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// Result 是成功归档的结果。Result describes a successful archive.
type Result struct {
	ArchiveID string
	PubkeyHex string
	DigestHex string
	Bytes     int
}

// Handle 实现 POST /v1/submissions：读原始字节→验签→落盘→回执。
// Handle serves one submission: read raw bytes, verify, persist, receipt.
func (s *Store) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, collector.CodeMalformedRequest, "not found")
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	pubkeyHex := strings.ToLower(strings.TrimSpace(r.Header.Get(collector.HeaderPubkey)))
	sigHex := strings.ToLower(strings.TrimSpace(r.Header.Get(collector.HeaderSignature)))
	sigVersion := strings.TrimSpace(r.Header.Get(collector.HeaderSigVersion))
	pubkey, err := collector.ParsePublicKeyHex(pubkeyHex)
	if err != nil || sigVersion != fmt.Sprint(collector.SigVersion) {
		writeError(w, http.StatusBadRequest, collector.CodeMalformedRequest, "bad headers")
		return
	}
	sigRaw, err := hex.DecodeString(sigHex)
	if err != nil || len(sigRaw) == 0 {
		writeError(w, http.StatusBadRequest, collector.CodeMalformedRequest, "bad signature encoding")
		return
	}
	digest := collector.DigestGzip(body)
	if err := collector.VerifyDigestSignature(pubkey, digest, sigRaw); err != nil {
		writeError(w, http.StatusUnauthorized, collector.CodeUnauthorized, "signature invalid")
		return
	}
	sigFile, err := collector.EncodeSigFile(digest, pubkey, sigRaw)
	if err != nil {
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "sig envelope failed")
		return
	}
	res, err := s.persist(pubkeyHex, digest, body, sigFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "persist failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"version":1,"archiveId":%q,"receivedAt":%q,"pubkeyHex":%q,"digestHex":%q,"bytes":%q}`,
		res.ArchiveID, s.now().Format(time.RFC3339), res.PubkeyHex, res.DigestHex, fmt.Sprint(res.Bytes))
}

func (s *Store) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	limit := s.MaxBodyBytes
	if limit <= 0 {
		limit = 32 << 20
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "read failed")
		return nil, false
	}
	if int64(len(body)) > limit {
		writeError(w, http.StatusRequestEntityTooLarge, collector.CodeMalformedRequest, "body too large")
		return nil, false
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, collector.CodeMalformedRequest, "empty body")
		return nil, false
	}
	return body, true
}

// persist 原子落盘：临时文件写 + fsync + 改名 + 目录 fsync，全部完成才成功。
// persist writes temp files, fsyncs, renames and fsyncs the directory.
func (s *Store) persist(pubkeyHex string, digest collector.Digest32, gzipBytes, sigFile []byte) (*Result, error) {
	now := s.now()
	dir := filepath.Join(s.Root,
		fmt.Sprintf("%04d", now.Year()),
		fmt.Sprintf("%02d", int(now.Month())),
		fmt.Sprintf("%02d", now.Day()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	archiveID := hex.EncodeToString(id)
	base := pubkeyHex + "-" + archiveID
	tmpGzip := filepath.Join(dir, base+".gzip.tmp")
	tmpSig := filepath.Join(dir, base+".sig.tmp")
	finalGzip := filepath.Join(dir, base+".gzip")
	finalSig := filepath.Join(dir, base+".sig")
	cleanup := func() {
		_ = os.Remove(tmpGzip)
		_ = os.Remove(tmpSig)
	}
	if err := writeSync(tmpGzip, gzipBytes); err != nil {
		cleanup()
		return nil, err
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
	return &Result{
		ArchiveID: archiveID,
		PubkeyHex: pubkeyHex,
		DigestHex: fmt.Sprintf("%x", digest),
		Bytes:     len(gzipBytes),
	}, nil
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
