package config

import (
	"io"
	"io/fs"
	"os"
	"time"
)

// FileSystem is an interface for file system operations.
// This abstraction enables testing config operations without touching the real filesystem.
type FileSystem interface {
	// ReadFile reads the named file and returns its contents.
	ReadFile(path string) ([]byte, error)
	// WriteFile writes data to the named file, creating it if necessary.
	WriteFile(path string, data []byte, perm os.FileMode) error
	// MkdirAll creates a directory named path, along with any necessary parents.
	MkdirAll(path string, perm os.FileMode) error
	// Stat returns a FileInfo describing the named file.
	Stat(path string) (os.FileInfo, error)
	// ReadDir reads the named directory and returns a list of directory entries.
	ReadDir(path string) ([]os.DirEntry, error)
	// RemoveAll removes path and any children it contains.
	RemoveAll(path string) error
	// OpenFile opens a file with the specified flags and permissions.
	OpenFile(name string, flag int, perm os.FileMode) (File, error)
	// UserHomeDir returns the current user's home directory.
	UserHomeDir() (string, error)
	// Getenv returns the value of the environment variable named by the key.
	Getenv(key string) string
}

// File represents an open file for locking operations.
type File interface {
	io.Closer
	Fd() uintptr
}

// DefaultFileSystem implements FileSystem using the real os package.
type DefaultFileSystem struct{}

func (d *DefaultFileSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (d *DefaultFileSystem) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (d *DefaultFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (d *DefaultFileSystem) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func (d *DefaultFileSystem) ReadDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}

func (d *DefaultFileSystem) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

func (d *DefaultFileSystem) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	return os.OpenFile(name, flag, perm)
}

func (d *DefaultFileSystem) UserHomeDir() (string, error) {
	return os.UserHomeDir()
}

func (d *DefaultFileSystem) Getenv(key string) string {
	return os.Getenv(key)
}

// fsys is the global FileSystem instance.
// It defaults to DefaultFileSystem but can be swapped for testing.
var fsys FileSystem = &DefaultFileSystem{}

// SetFileSystem sets the FileSystem instance for test injection.
// Returns the previous FileSystem so it can be restored after tests.
func SetFileSystem(f FileSystem) FileSystem {
	prev := fsys
	fsys = f
	return prev
}

// mockHomeDir is the default HomeDir used by MockFileSystem and tests.
const mockHomeDir = "/home/testuser"

// MockFileSystem is a FileSystem implementation for testing.
type MockFileSystem struct {
	Files      map[string][]byte        // path -> content
	Dirs       map[string]bool          // directories that exist
	DirEntries map[string][]os.DirEntry // path -> directory entries
	HomeDir    string
	EnvVars    map[string]string

	// Error injection
	ReadFileErr  error
	WriteFileErr error
	MkdirAllErr  error
	StatErr      error
	ReadDirErr   error
	RemoveAllErr error
	OpenFileErr  error
	HomeDirErr   error
}

// NewMockFileSystem creates a new MockFileSystem with initialized maps.
func NewMockFileSystem() *MockFileSystem {
	return &MockFileSystem{
		Files:      make(map[string][]byte),
		Dirs:       make(map[string]bool),
		DirEntries: make(map[string][]os.DirEntry),
		EnvVars:    make(map[string]string),
		HomeDir:    mockHomeDir,
	}
}

func (m *MockFileSystem) ReadFile(path string) ([]byte, error) {
	if m.ReadFileErr != nil {
		return nil, m.ReadFileErr
	}
	data, ok := m.Files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func (m *MockFileSystem) WriteFile(path string, data []byte, perm os.FileMode) error {
	if m.WriteFileErr != nil {
		return m.WriteFileErr
	}
	m.Files[path] = data
	return nil
}

func (m *MockFileSystem) MkdirAll(path string, perm os.FileMode) error {
	if m.MkdirAllErr != nil {
		return m.MkdirAllErr
	}
	m.Dirs[path] = true
	return nil
}

func (m *MockFileSystem) Stat(path string) (os.FileInfo, error) {
	if m.StatErr != nil {
		return nil, m.StatErr
	}
	if _, ok := m.Files[path]; ok {
		return &mockFileInfo{name: path, isDir: false}, nil
	}
	if m.Dirs[path] {
		return &mockFileInfo{name: path, isDir: true}, nil
	}
	return nil, os.ErrNotExist
}

func (m *MockFileSystem) ReadDir(path string) ([]os.DirEntry, error) {
	if m.ReadDirErr != nil {
		return nil, m.ReadDirErr
	}
	entries, ok := m.DirEntries[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return entries, nil
}

func (m *MockFileSystem) RemoveAll(path string) error {
	if m.RemoveAllErr != nil {
		return m.RemoveAllErr
	}
	delete(m.Files, path)
	delete(m.Dirs, path)
	return nil
}

func (m *MockFileSystem) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	if m.OpenFileErr != nil {
		return nil, m.OpenFileErr
	}
	return &mockFile{}, nil
}

func (m *MockFileSystem) UserHomeDir() (string, error) {
	if m.HomeDirErr != nil {
		return "", m.HomeDirErr
	}
	return m.HomeDir, nil
}

func (m *MockFileSystem) Getenv(key string) string {
	return m.EnvVars[key]
}

// mockFileInfo implements os.FileInfo for testing.
type mockFileInfo struct {
	name  string
	isDir bool
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return 0 }
func (m *mockFileInfo) Mode() fs.FileMode  { return 0o644 }
func (m *mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m *mockFileInfo) IsDir() bool        { return m.isDir }
func (m *mockFileInfo) Sys() any           { return nil }

// mockFile implements File for testing.
type mockFile struct{}

func (m *mockFile) Close() error { return nil }
func (m *mockFile) Fd() uintptr  { return 0 }

// mockDirEntry implements os.DirEntry for testing.
type mockDirEntry struct {
	nameVal  string
	isDirVal bool
}

func (m *mockDirEntry) Name() string               { return m.nameVal }
func (m *mockDirEntry) IsDir() bool                { return m.isDirVal }
func (m *mockDirEntry) Type() fs.FileMode          { return 0 }
func (m *mockDirEntry) Info() (fs.FileInfo, error) { return nil, nil } //nolint:nilnil // satisfies fs.DirEntry interface
