package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config 是接收服务的全部配置。Config is the receiver configuration.
type Config struct {
	// Listen 是监听地址，如 127.0.0.1:18080。Listen address.
	Listen string `json:"listen"`
	// ArchiveRoot 是归档根目录。Archive root directory.
	ArchiveRoot string `json:"archiveRoot"`
	// MaxBodyBytes 是请求体上限，缺省 32 MiB。Request body cap.
	MaxBodyBytes int64 `json:"maxBodyBytes"`
	// MaxConcurrent 是并发上限，缺省 32。Concurrency cap.
	MaxConcurrent int `json:"maxConcurrent"`
}

// Defaults 返回缺省配置。Defaults returns the default configuration.
func Defaults() Config {
	return Config{
		Listen:        "127.0.0.1:18080",
		ArchiveRoot:   "./archive",
		MaxBodyBytes:  32 << 20,
		MaxConcurrent: 32,
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
	if cfg.MaxBodyBytes <= 0 {
		return Config{}, fmt.Errorf("config: maxBodyBytes must be positive")
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 32
	}
	return cfg, nil
}
