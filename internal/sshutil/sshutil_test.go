package sshutil

import (
	"reflect"
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

func TestCommonOptions(t *testing.T) {
	paths := &config.Paths{
		SSHKey:     "/home/user/.ssh/abox_key",
		KnownHosts: "/home/user/.local/share/abox/instances/test/known_hosts",
	}

	options := CommonOptions(paths)

	expected := []string{
		"-i", "/home/user/.ssh/abox_key",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=/home/user/.local/share/abox/instances/test/known_hosts",
		"-o", "ControlPath=none",
		"-o", "LogLevel=ERROR",
	}

	if !reflect.DeepEqual(options, expected) {
		t.Errorf("CommonOptions() = %v, want %v", options, expected)
	}
}

func TestTarget(t *testing.T) {
	tests := []struct {
		name     string
		user     string
		ip       string
		expected string
	}{
		{"basic", "ubuntu", "10.10.10.2", "ubuntu@10.10.10.2"},
		{"root", "root", "192.168.1.100", "root@192.168.1.100"},
		{"custom-user", "myuser", "172.16.0.5", "myuser@172.16.0.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Target(tt.user, tt.ip)
			if result != tt.expected {
				t.Errorf("Target(%q, %q) = %q, want %q", tt.user, tt.ip, result, tt.expected)
			}
		})
	}
}

func TestBuildSSHArgs(t *testing.T) {
	paths := &config.Paths{
		SSHKey:     "/path/to/key",
		KnownHosts: "/path/to/known_hosts",
	}

	tests := []struct {
		name     string
		user     string
		ip       string
		cmd      []string
		expected []string
	}{
		{
			name:     "no-command",
			user:     "ubuntu",
			ip:       "10.10.10.2",
			cmd:      nil,
			expected: []string{"-i", "/path/to/key", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/path/to/known_hosts", "-o", "ControlPath=none", "-o", "LogLevel=ERROR", "ubuntu@10.10.10.2"},
		},
		{
			name:     "single-command",
			user:     "ubuntu",
			ip:       "10.10.10.2",
			cmd:      []string{"ls", "-la"},
			expected: []string{"-i", "/path/to/key", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/path/to/known_hosts", "-o", "ControlPath=none", "-o", "LogLevel=ERROR", "ubuntu@10.10.10.2", "ls", "-la"},
		},
		{
			name:     "complex-command",
			user:     "root",
			ip:       "192.168.1.1",
			cmd:      []string{"cat", "/etc/hosts"},
			expected: []string{"-i", "/path/to/key", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/path/to/known_hosts", "-o", "ControlPath=none", "-o", "LogLevel=ERROR", "root@192.168.1.1", "cat", "/etc/hosts"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildSSHArgs(paths, tt.user, tt.ip, tt.cmd...)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("BuildSSHArgs() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestBuildSCPArgs(t *testing.T) {
	paths := &config.Paths{
		SSHKey:     "/path/to/key",
		KnownHosts: "/path/to/known_hosts",
	}

	tests := []struct {
		name      string
		source    string
		dest      string
		recursive bool
		expected  []string
	}{
		{
			name:      "non-recursive",
			source:    "/local/file.txt",
			dest:      "user@host:/remote/path",
			recursive: false,
			expected:  []string{"-O", "-i", "/path/to/key", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/path/to/known_hosts", "-o", "ControlPath=none", "-o", "LogLevel=ERROR", "/local/file.txt", "user@host:/remote/path"},
		},
		{
			name:      "recursive",
			source:    "/local/dir",
			dest:      "user@host:/remote/path",
			recursive: true,
			expected:  []string{"-r", "-O", "-i", "/path/to/key", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/path/to/known_hosts", "-o", "ControlPath=none", "-o", "LogLevel=ERROR", "/local/dir", "user@host:/remote/path"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildSCPArgs(paths, tt.source, tt.dest, tt.recursive)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("BuildSCPArgs() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRemotePath(t *testing.T) {
	tests := []struct {
		name     string
		user     string
		ip       string
		path     string
		expected string
	}{
		{"basic", "ubuntu", "10.10.10.2", "/home/ubuntu/file.txt", "ubuntu@10.10.10.2:/home/ubuntu/file.txt"},
		{"root-path", "root", "192.168.1.1", "/etc/hosts", "root@192.168.1.1:/etc/hosts"},
		{"relative-path", "user", "host", "relative/path", "user@host:relative/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemotePath(tt.user, tt.ip, tt.path)
			if result != tt.expected {
				t.Errorf("RemotePath(%q, %q, %q) = %q, want %q", tt.user, tt.ip, tt.path, result, tt.expected)
			}
		})
	}
}
