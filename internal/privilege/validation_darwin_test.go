//go:build darwin

package privilege

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

// currentUserServer returns a PrivilegeServer whose allowedUID is the current
// user's UID, plus that user's home directory. Path validators verify the home
// dir is owned by allowedUID, so positive tests must use the real home (which
// t.TempDir() is not under). Tests run unprivileged.
func currentUserServer(t *testing.T) (*PrivilegeServer, string) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current() failed: %v", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatalf("parse uid %q: %v", u.Uid, err)
	}
	home := u.HomeDir
	if home == "" || !filepath.IsAbs(home) {
		t.Skipf("no usable home directory for current user: %q", home)
	}
	return &PrivilegeServer{allowedUID: uid}, home
}

// storageRoot returns <home>/Library/Application Support/abox.
func storageRoot(home string) string {
	return filepath.Join(home, "Library", "Application Support", "abox")
}

func TestValidatePathDarwin(t *testing.T) {
	s, home := currentUserServer(t)
	root := storageRoot(home)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid disk dir", filepath.Join(root, "images", "instances", "myvm"), false},
		{"valid base image", filepath.Join(root, "images", "base", "img.qcow2"), false},
		{"exact root", root, false},
		{"traversal raw", filepath.Join(root, "..", "..", "etc", "passwd"), true},
		{"traversal at start", "../" + root, true},
		{"outside root - tmp", "/tmp/malicious.qcow2", true},
		{"outside root - etc", "/etc/passwd", true},
		{"root path", "/", true},
		{"empty path", "", true},
		{"other users home", "/Users/someone-else/Library/Application Support/abox/x", true},
		{"close but not allowed", filepath.Join(home, "Library", "Application Support", "aboxextra", "f"), true},
		{"home but not abox storage", filepath.Join(home, ".ssh", "id_rsa"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.ValidatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRemoveAllPathDarwin(t *testing.T) {
	s, home := currentUserServer(t)
	root := storageRoot(home)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid deep path", filepath.Join(root, "images", "instances", "myvm"), false},
		{"one level deep - 6 components", filepath.Join(root, "images"), false},
		{"exact root - too shallow (5 components)", root, true},
		{"traversal", filepath.Join(root, "..", "..", "etc"), true},
		{"outside allowed", "/tmp/something/deep/path/here", true},
		{"other users storage deep", "/Users/someone-else/Library/Application Support/abox/images", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.ValidateRemoveAllPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRemoveAllPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

// TestValidatePathNoSymlinksDarwin exercises the symlink-escape containment:
// a symlink inside the (existing) abox storage root that points outside it must
// be rejected once resolved.
func TestValidatePathNoSymlinksDarwin(t *testing.T) {
	s, home := currentUserServer(t)
	root := storageRoot(home)

	// Build a real, owned subtree under the storage root for this test, then
	// clean it up. This keeps the positive case ownership-verified.
	testDir := filepath.Join(root, "images", "instances", ".abox-f1-test")
	if err := os.MkdirAll(testDir, 0o755); err != nil {
		t.Skipf("cannot create test dir under storage root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(root, "images", "instances", ".abox-f1-test")) })

	// A regular file under the root resolves to itself -> allowed.
	regular := filepath.Join(testDir, "disk.qcow2")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}
	if err := s.ValidatePathNoSymlinks(regular); err != nil {
		t.Errorf("ValidatePathNoSymlinks(%q) = %v, want nil", regular, err)
	}

	// A not-yet-existing path whose existing ancestor is under the root -> allowed.
	notYet := filepath.Join(testDir, "subdir", "new.qcow2")
	if err := s.ValidatePathNoSymlinks(notYet); err != nil {
		t.Errorf("ValidatePathNoSymlinks(%q) = %v, want nil", notYet, err)
	}

	// A symlink under the root pointing outside it must be rejected once resolved.
	escape := filepath.Join(testDir, "escape")
	if err := os.Symlink("/etc/passwd", escape); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := s.ValidatePathNoSymlinks(escape); err == nil {
		t.Errorf("ValidatePathNoSymlinks(%q) = nil, want symlink-escape error", escape)
	}
}

// TestValidateArgsDarwin verifies that ValidateArgs on macOS accepts paths
// containing a space (required for "~/Library/Application Support/abox") while
// still rejecting shell metacharacters, null bytes, newlines, and glob chars.
func TestValidateArgsDarwin(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		// macOS abox storage paths that contain a space must be accepted.
		{"application support path", []string{"/Users/x/Library/Application Support/abox/images/base/img.qcow2"}, false},
		{"application support dir", []string{"/Users/x/Library/Application Support/abox"}, false},
		{"space in intermediate segment", []string{"/Users/Some User/Library/Application Support/abox/disk.qcow2"}, false},

		// Paths without spaces still work.
		{"no space path", []string{"/Users/x/.local/share/abox/instances/myvm/disk.qcow2"}, false},

		// Shell metacharacters must still be rejected.
		{"semicolon", []string{"file;evil"}, true},
		{"pipe", []string{"file|evil"}, true},
		{"ampersand", []string{"file&evil"}, true},
		{"dollar", []string{"$HOME"}, true},
		{"backtick", []string{"`whoami`"}, true},
		{"backslash", []string{`cmd\n`}, true},
		{"angle bracket lt", []string{"<input"}, true},
		{"angle bracket gt", []string{"output>"}, true},
		{"parentheses", []string{"$(cmd)"}, true},
		{"curly braces", []string{"{a,b}"}, true},

		// Whitespace other than space must still be rejected.
		{"null byte", []string{"file\x00evil"}, true},
		{"newline", []string{"file\nevil"}, true},
		{"carriage return", []string{"file\revil"}, true},
		{"tab", []string{"file\tevil"}, true},

		// Glob characters must still be rejected.
		{"glob star", []string{"file*"}, true},
		{"glob question", []string{"file?"}, true},
		{"glob brackets", []string{"file[0]"}, true},

		// Miscellaneous characters that must remain rejected.
		{"unicode", []string{"fileé"}, true},
		{"tilde", []string{"~/file"}, true},
		{"hash", []string{"file#1"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateArgs(%v) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}
}
