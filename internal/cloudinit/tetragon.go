package cloudinit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sandialabs/abox/internal/errhint"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/tetragon"
)

// EnsureTetragonCached ensures the Tetragon tarball is downloaded and cached.
// Returns the path to the cached tarball.
func EnsureTetragonCached(ctx context.Context, w io.Writer, cacheDir string, release *tetragon.ReleaseInfo) (string, error) {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil { //nolint:gosec // cache dir needs 0o755 for user access
		return "", fmt.Errorf("failed to create cache directory: %w", err)
	}

	tarballPath := filepath.Join(cacheDir, tetragon.TarballFilename(release.Version))

	// Check if already cached and valid
	if release.Hash != "" && checkTetragonCached(tarballPath, release.Hash) {
		logging.Debug("tetragon tarball already cached", "path", tarballPath)
		return tarballPath, nil
	}

	// Download and verify
	if err := downloadTetragon(ctx, w, tarballPath, release); err != nil {
		return "", err
	}

	return tarballPath, nil
}

// checkTetragonCached verifies the cached tarball exists and has correct checksum.
func checkTetragonCached(path, expectedHash string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return false
	}

	computedHash := hex.EncodeToString(hasher.Sum(nil))
	return computedHash == expectedHash
}

// downloadTetragon downloads the Tetragon tarball with progress and verifies checksum.
func downloadTetragon(ctx context.Context, w io.Writer, destPath string, release *tetragon.ReleaseInfo) error {
	fmt.Fprintf(w, "Downloading Tetragon %s...\n", release.Version)
	fmt.Fprintf(w, "URL: %s\n", release.URL)

	// Download to temp file first
	tempPath := destPath + ".download"
	defer os.Remove(tempPath)

	client := &http.Client{Timeout: 30 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, release.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download: HTTP %d", resp.StatusCode)
	}

	out, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	hasher := sha256.New()
	if err := downloadToFile(w, resp.Body, out, hasher, resp.ContentLength); err != nil {
		out.Close()
		return err
	}
	out.Close()
	fmt.Fprintln(w)

	computedHash := hex.EncodeToString(hasher.Sum(nil))
	if err := verifyChecksum(w, computedHash, release.Hash); err != nil {
		return err
	}

	// Move to final location
	if err := os.Rename(tempPath, destPath); err != nil {
		return fmt.Errorf("failed to save tarball: %w", err)
	}

	logging.Audit("tetragon tarball downloaded",
		"action", logging.ActionTetragonDownload,
		"version", release.Version,
		"path", destPath,
	)

	return nil
}

// downloadToFile reads from body into out and hasher, showing progress.
func downloadToFile(w io.Writer, body io.Reader, out *os.File, hasher io.Writer, size int64) error {
	buf := make([]byte, 32*1024)
	downloaded := int64(0)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return fmt.Errorf("failed to write: %w", werr)
			}
			if _, werr := hasher.Write(buf[:n]); werr != nil {
				return fmt.Errorf("failed to update hash: %w", werr)
			}
			downloaded += int64(n)
			if size > 0 {
				pct := float64(downloaded) / float64(size) * 100
				fmt.Fprintf(w, "\r  %.1f%% (%.1f / %.1f MB)", pct,
					float64(downloaded)/(1024*1024),
					float64(size)/(1024*1024))
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to download: %w", err)
		}
	}
}

func abbreviateHash(hash string) string {
	if len(hash) > 16 {
		return hash[:16] + "..."
	}
	return hash
}

// verifyChecksum verifies or reports the computed hash.
func verifyChecksum(w io.Writer, computedHash, expectedHash string) error {
	if expectedHash != "" {
		fmt.Fprintln(w, "Verifying SHA256 checksum...")
		if computedHash != expectedHash {
			return &errhint.ErrHint{
				Err:  errors.New("checksum mismatch"),
				Hint: fmt.Sprintf("expected: %s\ncomputed: %s", expectedHash, computedHash),
			}
		}
		fmt.Fprintf(w, "Checksum verified: %s\n", abbreviateHash(computedHash))
	} else {
		fmt.Fprintf(w, "Downloaded (SHA256: %s)\n", abbreviateHash(computedHash))
	}
	return nil
}
