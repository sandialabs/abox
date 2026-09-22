// Package shared holds the record layer for the `abox mount` subcommands. It
// persists mount records (mounts.json) under an instance directory and is
// depended on by mount/add, mount/list, and mount/remove. It must not import any
// pkg/cmd/* package so those verb packages can depend on it without a cycle.
package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// MountEntry represents a single mount record.
type MountEntry struct {
	LocalPath  string    `json:"local_path"`
	RemotePath string    `json:"remote_path"`
	MountedAt  time.Time `json:"mounted_at"`
}

// MountsFile represents the mounts.json structure.
type MountsFile struct {
	Mounts []MountEntry `json:"mounts"`
}

// getMountsFilePath returns the path to mounts.json for an instance.
func getMountsFilePath(instanceDir string) string {
	return filepath.Join(instanceDir, "mounts.json")
}

// loadMounts loads the mounts file for an instance.
func loadMounts(instanceDir string) (*MountsFile, error) {
	path := getMountsFilePath(instanceDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &MountsFile{Mounts: []MountEntry{}}, nil
	}
	if err != nil {
		return nil, err
	}

	var mounts MountsFile
	if err := json.Unmarshal(data, &mounts); err != nil {
		return nil, err
	}
	return &mounts, nil
}

// saveMounts saves the mounts file for an instance.
func saveMounts(instanceDir string, mounts *MountsFile) error {
	path := getMountsFilePath(instanceDir)
	data, err := json.MarshalIndent(mounts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// AddMountRecord adds a mount to the mounts file.
func AddMountRecord(instanceDir, localPath, remotePath string) error {
	mounts, err := loadMounts(instanceDir)
	if err != nil {
		return err
	}

	mounts.Mounts = append(mounts.Mounts, MountEntry{
		LocalPath:  localPath,
		RemotePath: remotePath,
		MountedAt:  time.Now(),
	})

	return saveMounts(instanceDir, mounts)
}

// RemoveMountRecord removes a mount from the mounts file.
func RemoveMountRecord(instanceDir, localPath string) error {
	mounts, err := loadMounts(instanceDir)
	if err != nil {
		return err
	}

	filtered := make([]MountEntry, 0, len(mounts.Mounts))
	for _, m := range mounts.Mounts {
		if m.LocalPath != localPath {
			filtered = append(filtered, m)
		}
	}
	mounts.Mounts = filtered

	return saveMounts(instanceDir, mounts)
}

// GetMounts returns all mounts for an instance.
func GetMounts(instanceDir string) ([]MountEntry, error) {
	mounts, err := loadMounts(instanceDir)
	if err != nil {
		return nil, err
	}
	return mounts.Mounts, nil
}
