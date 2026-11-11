package archive

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bsv8/BitFSCollector/internal/auth"
	"github.com/bsv8/BitFSCollector/internal/manifest"
	collector "github.com/bsv8/BitFSCollectorProtocol/collector"
)

// V2 是内网接管接口：清单、下载、确认，均需 Bearer。
// V2 serves intranet takeover: list, download and ack behind bearer auth.
type V2 struct {
	// Manifest 是接管清单。Takeover manifest.
	Manifest *manifest.DB
	// Auth 校验 Bearer。Bearer verifier.
	Auth *auth.Verifier
	// MaxDownloadBytes 是下载上限。Download cap.
	MaxDownloadBytes int64
	// Now 由调用方注入时钟。Injected clock.
	Now func() time.Time
}

func (v *V2) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now().UTC()
}

func (v *V2) maxDownload() int64 {
	if v.MaxDownloadBytes > 0 {
		return v.MaxDownloadBytes
	}
	return 32 << 20
}

func (v *V2) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if v.Auth == nil || !v.Auth.Configured() {
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "pull auth not configured")
		return false
	}
	if !v.Auth.Valid(r.Header.Get(collector.ArchiveAuthHeader)) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"code":%q,"message":%q}`, string(collector.CodeUnauthorized), "bad bearer")
		return false
	}
	return true
}

// HandleList 实现 GET /v2/archives?after=&limit=：按 sequence 升序分页。
func (v *V2) HandleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusNotFound, collector.CodeMalformedRequest, "not found")
		return
	}
	if !v.checkAuth(w, r) {
		return
	}
	after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if err != nil || after < 0 {
		after = 0
		if r.URL.Query().Get("after") != "" {
			writeError(w, http.StatusBadRequest, collector.CodeMalformedRequest, "bad after")
			return
		}
	}
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			writeError(w, http.StatusBadRequest, collector.CodeMalformedRequest, "bad limit")
			return
		}
		limit = n
	}
	if err := collector.ValidateListParams(after, limit); err != nil {
		writeError(w, http.StatusBadRequest, collector.CodeMalformedRequest, "bad pagination")
		return
	}
	rows, err := v.Manifest.ListPending(after, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "list failed")
		return
	}
	items := make([]collector.ArchiveSummary, 0, len(rows))
	next := after
	for _, rec := range rows {
		items = append(items, collector.ArchiveSummary{
			ArchiveID: rec.ArchiveID, Sequence: rec.Sequence, ReceivedAt: rec.ReceivedAt,
			PubkeyHex: rec.PubkeyHex, DigestHex: rec.DigestHex, Bytes: rec.Bytes,
		})
		if rec.Sequence > next {
			next = rec.Sequence
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(collector.ListArchivesResponse{Archives: items, NextAfter: next})
}

// route 解析 /v2/archives/{id}/{gzip,sig,ack}。
func (v *V2) route(path string) (id, action string, ok bool) {
	rest, found := strings.CutPrefix(path, collector.ArchivesPath+"/")
	if !found || rest == "" {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		return "", "", false
	}
	if err := collector.ValidateArchiveID(parts[0]); err != nil {
		return "", "", false
	}
	switch parts[1] {
	case "gzip", "sig", "ack":
		return parts[0], parts[1], true
	}
	return "", "", false
}

// HandleArtifact 实现下载与确认（路由后分发）。
func (v *V2) HandleArtifact(w http.ResponseWriter, r *http.Request) {
	id, action, ok := v.route(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, collector.CodeMalformedRequest, "not found")
		return
	}
	if !v.checkAuth(w, r) {
		return
	}
	switch action {
	case "gzip":
		v.serveFile(w, r, id, true)
	case "sig":
		v.serveFile(w, r, id, false)
	case "ack":
		v.handleAck(w, r, id)
	}
}

func (v *V2) serveFile(w http.ResponseWriter, r *http.Request, id string, gzip bool) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusNotFound, collector.CodeMalformedRequest, "not found")
		return
	}
	rec, err := v.Manifest.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, collector.CodeMalformedRequest, "archive not found")
		return
	}
	if rec.State == "cleaned" {
		writeError(w, http.StatusNotFound, collector.CodeMalformedRequest, "archive cleaned")
		return
	}
	path := rec.GzipPath
	contentType := collector.ContentType
	if !gzip {
		path = rec.SigPath
		contentType = "application/json"
	}
	f, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusNotFound, collector.CodeMalformedRequest, "artifact missing")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > v.maxDownload() {
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "artifact too large")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = f.WriteTo(w)
}

func (v *V2) handleAck(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, collector.CodeMalformedRequest, "not found")
		return
	}
	rec, err := v.Manifest.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, collector.CodeMalformedRequest, "archive not found")
		return
	}
	at := v.now().Format(time.RFC3339)
	if rec.State == "acknowledged" || rec.State == "cleaned" {
		// 重复确认：已接管未清理时补删文件，删除并同步目录成功后才记清理完成；
		// 失败返回 500 以便持续重试，已清理直接成功。
		if rec.State == "acknowledged" {
			if err := cleanupFiles(rec); err != nil {
				writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "cleanup failed")
				return
			}
			if err := v.Manifest.MarkCleaned(id); err != nil {
				writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "cleanup failed")
				return
			}
		}
		writeAck(w, id, at, true)
		return
	}
	repeated, err := v.Manifest.MarkAcknowledged(id, at)
	if err != nil {
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "ack failed")
		return
	}
	if repeated {
		writeAck(w, id, at, true)
		return
	}
	// ack 成功后删除原始文件并记清理完成；删除或目录同步失败返回 500 以便内网重试。
	if err := cleanupFiles(rec); err != nil {
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "cleanup failed")
		return
	}
	if err := v.Manifest.MarkCleaned(id); err != nil {
		writeError(w, http.StatusInternalServerError, collector.CodeStorageFailed, "cleanup failed")
		return
	}
	writeAck(w, id, at, false)
}

// cleanupFiles 删除归档对并同步所在目录：全部成功才算清理完成。
// 不存在视为已删；其他错误必须重试，不得标记完成。
// cleanupFiles removes the archive pair and syncs parent dirs.
func cleanupFiles(rec *manifest.Record) error {
	if err := os.Remove(rec.GzipPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(rec.SigPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	dirs := map[string]bool{}
	for _, p := range []string{rec.GzipPath, rec.SigPath} {
		dirs[filepath.Dir(p)] = true
	}
	for dir := range dirs {
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func writeAck(w http.ResponseWriter, id, at string, repeated bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(collector.AckResponse{ArchiveID: id, AcknowledgedAt: at, Repeated: repeated})
}
