// cmd/gendocs generates man pages and shell completion scripts for abox.
// It is invoked by GoReleaser as a before-hook and writes output outside
// of dist/ to avoid conflicts with GoReleaser's clean check.
package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	cobradoc "github.com/spf13/cobra/doc"

	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/root"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cmd := root.NewCmdRoot(factory.New())
	cmd.DisableAutoGenTag = true

	// Generate man pages
	manDir := "manpages"
	if err := os.MkdirAll(manDir, 0o755); err != nil { //nolint:gosec // output dir
		return fmt.Errorf("create man dir: %w", err)
	}

	header := &cobradoc.GenManHeader{Section: "1"}
	if err := cobradoc.GenManTree(cmd, header, manDir); err != nil {
		return fmt.Errorf("generate man pages: %w", err)
	}

	// Gzip each .1 file (Debian convention)
	manFiles, err := filepath.Glob(filepath.Join(manDir, "*.1"))
	if err != nil {
		return err
	}
	for _, path := range manFiles {
		if err := gzipFile(path); err != nil {
			return fmt.Errorf("gzip %s: %w", path, err)
		}
	}

	// Generate shell completions
	compDir := "completions"
	if err := os.MkdirAll(compDir, 0o755); err != nil { //nolint:gosec // output dir
		return fmt.Errorf("create completions dir: %w", err)
	}

	// Bash
	bashFile, err := os.Create(filepath.Join(compDir, "abox.bash"))
	if err != nil {
		return err
	}
	defer bashFile.Close()
	if err := cmd.GenBashCompletionV2(bashFile, true); err != nil {
		return fmt.Errorf("generate bash completion: %w", err)
	}

	// Zsh
	zshFile, err := os.Create(filepath.Join(compDir, "_abox"))
	if err != nil {
		return err
	}
	defer zshFile.Close()
	if err := cmd.GenZshCompletion(zshFile); err != nil {
		return fmt.Errorf("generate zsh completion: %w", err)
	}

	// Fish
	fishFile, err := os.Create(filepath.Join(compDir, "abox.fish"))
	if err != nil {
		return err
	}
	defer fishFile.Close()
	if err := cmd.GenFishCompletion(fishFile, true); err != nil {
		return fmt.Errorf("generate fish completion: %w", err)
	}

	return nil
}

// gzipFile compresses a file in place, replacing it with a .gz version.
func gzipFile(path string) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(path + ".gz")
	if err != nil {
		return err
	}
	defer dst.Close()

	gz := gzip.NewWriter(dst)
	if _, err := io.Copy(gz, src); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}

	return os.Remove(path)
}
