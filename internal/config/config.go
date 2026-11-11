package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config 是接收服务的全部配置。Config is the receiver configuration.
type Config struct {
	// Listen 是监听地址，如 127.0.0.1:18080。Listen address.
	Listen string `json:"listen"`
	// ArchiveRoot 是归档根目录。Archive root directory.
	ArchiveRoot string `json:"archiveRoot"`
	// ManifestPath 是接管清单 SQLite 路径，缺省为归档根下 manifest.db。Manifest database path.
	ManifestPath string `json:"manifestPath"`
	// MaxBodyBytes 是请求体上限，缺省 32 MiB。Request body cap.
	MaxBodyBytes int64 `json:"maxBodyBytes"`
	// MaxConcurrent 是并发上限，缺省 32。Concurrency cap.
	MaxConcurrent int `json:"maxConcurrent"`
	// MinFreeBytes 是磁盘可用下限，低于则拒绝新提交（429），缺省 1 GiB。Free-space floor.
	MinFreeBytes int64 `json:"minFreeBytes"`
	// PullTokens 是 v2 拉取 Bearer（支持双 Token 轮换，秘密只存本机配置）。Pull bearer tokens.
	PullTokens []string `json:"pullTokens"`
}

// Defaults 返回缺省配置。Defaults returns the default configuration.
func Defaults() Config {
	return Config{
		Listen:        "127.0.0.1:18080",
		ArchiveRoot:   "./archive",
		ManifestPath:  "",
		MaxBodyBytes:  32 << 20,
		MaxConcurrent: 32,
		MinFreeBytes:  1 << 30,
		PullTokens:    nil,
	}
}

// Load 读取 JSON 配置并校验，未填字段取缺省。Load reads and validates config.
func Load(path string) (Config, error) {
	cfg := Defaults()
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if cfg.Listen == "" {
		return Config{}, fmt.Errorf("config: listen is required")
	}
	if cfg.ArchiveRoot == "" {
		return Config{}, fmt.Errorf("config: archiveRoot is required")
	}
	if cfg.ManifestPath == "" {
		cfg.ManifestPath = filepath.Join(cfg.ArchiveRoot, "manifest.db")
	}
	if cfg.MaxBodyBytes <= 0 {
		return Config{}, fmt.Errorf("config: maxBodyBytes must be positive")
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 32
	}
	if cfg.MinFreeBytes < 0 {
		return Config{}, fmt.Errorf("config: minFreeBytes must not be negative")
	}
	return cfg, nil
}
