package secrets

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Key-file discovery order is defined in the Rust core (core/src/secrets.rs);
// OpenBao.md section 2.1 is the written authority. The core runs sandboxed, so
// this host gathers the facts it decides from (environment, standard
// directories, the users under /home) and checks which candidate exists.

type pathContext struct {
	OracleKeyPath    string   `json:"oracle_key_path"`
	KnirvRootKeyPath string   `json:"knirv_root_key_path"`
	KnirvBootKeyPath string   `json:"knirv_boot_key_path"`
	KnirvConfigDir   string   `json:"knirv_config_dir"`
	SudoUser         string   `json:"sudo_user"`
	UserConfigDir    string   `json:"user_config_dir"`
	HomeDir          string   `json:"home_dir"`
	ExeDir           string   `json:"exe_dir"`
	Cwd              string   `json:"cwd"`
	HomeRoot         string   `json:"home_root"`
	HomeUsers        []string `json:"home_users"`
	EtcDir           string   `json:"etc_dir"`
}

func currentPathContext() pathContext {
	c := pathContext{
		OracleKeyPath:    os.Getenv("ORACLE_KEY_PATH"),
		KnirvRootKeyPath: os.Getenv("KNIRV_ROOT_KEY_PATH"),
		KnirvBootKeyPath: os.Getenv("KNIRV_BOOT_KEY_PATH"),
		KnirvConfigDir:   os.Getenv("KNIRV_CONFIG_DIR"),
		SudoUser:         os.Getenv("SUDO_USER"),
		HomeRoot:         "/home",
		EtcDir:           "/etc",
	}
	c.UserConfigDir, _ = os.UserConfigDir()
	c.HomeDir, _ = os.UserHomeDir()
	if exe, err := os.Executable(); err == nil {
		c.ExeDir = filepath.Dir(exe)
	}
	c.Cwd, _ = os.Getwd()
	if entries, err := os.ReadDir(c.HomeRoot); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				c.HomeUsers = append(c.HomeUsers, entry.Name())
			}
		}
		sort.Strings(c.HomeUsers)
	}
	return c
}

func searchPaths(kind string) []string {
	var out struct {
		Paths []string `json:"paths"`
	}
	if err := call("secrets.search_paths", map[string]any{"kind": kind, "context": currentPathContext()}, &out); err != nil {
		panic("secrets: core search_paths failed: " + err.Error())
	}
	return out.Paths
}

func find(kind string) string {
	for _, path := range searchPaths(kind) {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

// BootSearchPaths returns the boot.key search order.
func BootSearchPaths() []string { return searchPaths("boot") }

// RootSearchPaths returns the root.key search order, including the hidden
// .key directories, the SUDO_USER fallback, and the /home/* scan.
func RootSearchPaths() []string { return searchPaths("root") }

// FindBoot returns the first existing boot.key path, or "".
func FindBoot() string { return find("boot") }

// FindRoot returns the first existing root.key path, or "".
func FindRoot() string { return find("root") }
