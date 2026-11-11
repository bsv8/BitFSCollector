package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bsv8/BitFSCollector/internal/manifest"
	collector "github.com/bsv8/BitFSCollectorProtocol/collector"
)

// Recover 启动恢复：清临时文件，将有完整文件对但无清单行的归档重新记为待接管。
// 半份归档不进入清单；DB 有行但文件缺失的交运维处理。
// Recover cleans temp files and re-manifests complete file pairs missing from the DB.
func Recover(root string, db *manifest.DB, maxBytes int64) (relisted int, err error) {
	if err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".tmp") {
			_ = os.Remove(path)
			return nil
		}
		if !strings.HasSuffix(path, ".gzip") {
			return nil
		}
		base := strings.TrimSuffix(filepath.Base(path), ".gzip")
		sep := strings.LastIndex(base, "-")
		if sep < 0 {
			return nil
		}
		pubkeyHex, archiveID := base[:sep], base[sep+1:]
		if err := collector.ValidateArchiveID(archiveID); err != nil {
			return nil
		}
		if _, err := collector.ParsePublicKeyHex(pubkeyHex); err != nil {
			return nil
		}
		sigPath := filepath.Join(filepath.Dir(path), base+".sig")
		if _, err := os.Stat(sigPath); err != nil {
			return nil
		}
		if _, err := db.Get(archiveID); err == nil {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil || (maxBytes > 0 && int64(len(raw)) > maxBytes) {
			return nil
		}
		h := sha256.New()
		h.Write([]byte(collector.SignatureDomain))
		h.Write(raw)
		digestHex := hex.EncodeToString(h.Sum(nil))
		sigRaw, err := os.ReadFile(sigPath)
		if err != nil {
			return nil
		}
		var doc map[string]any
		if err := json.Unmarshal(sigRaw, &doc); err != nil {
			return nil
		}
		if docDigest, _ := doc["digestHex"].(string); docDigest != "" && docDigest != digestHex {
			return nil
		}
		receivedAt := info.ModTime().UTC().Format(time.RFC3339)
		if _, _, err := db.InsertPendingIgnore(archiveID, receivedAt, pubkeyHex, digestHex, int64(len(raw)), path, sigPath); err != nil {
			return fmt.Errorf("recover %s: %w", archiveID, err)
		}
		relisted++
		return nil
	}); err != nil {
		return relisted, err
	}
	return relisted, nil
}

// RecoverCleanup 启动补偿：对已接管未清理的行补删文件，删除并同步目录成功后才记完成。
// 单行失败不中断其余行，返回清理数与首个错误，下次启动或重复确认继续。
// RecoverCleanup finishes acknowledged-but-uncleaned rows after a crash.
func RecoverCleanup(db *manifest.DB) (cleaned int, err error) {
	rows, err := db.ListByState("acknowledged")
	if err != nil {
		return 0, err
	}
	var firstErr error
	for i := range rows {
		if cerr := cleanupFiles(&rows[i]); cerr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("cleanup %s: %w", rows[i].ArchiveID, cerr)
			}
			continue
		}
		if merr := db.MarkCleaned(rows[i].ArchiveID); merr != nil {
			if firstErr == nil {
				firstErr = merr
			}
			continue
		}
		cleaned++
	}
	return cleaned, firstErr
}
