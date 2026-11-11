package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsManifestAndFloor(t *testing.T) {
	dir := t.TempDir()
	raw := `{"listen":"127.0.0.1:18099","archiveRoot":"` + dir + `"}`
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ManifestPath != filepath.Join(dir, "manifest.db") {
		t.Fatalf("manifest default mismatch: %q", cfg.ManifestPath)
	}
	if cfg.MaxBodyBytes != 32<<20 || cfg.MaxConcurrent != 32 || cfg.MinFreeBytes != 1<<30 {
		t.Fatalf("defaults mismatch: %+v", cfg)
	}
	if len(cfg.PullTokens) != 0 {
		t.Fatalf("tokens must default empty: %+v", cfg)
	}
}

func TestLoadRejectsNegativeFloor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"listen":"x","archiveRoot":"y","maxBodyBytes":1,"minFreeBytes":-1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("negative minFreeBytes must fail")
	}
}
