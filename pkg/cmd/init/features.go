package init

import "embed"

//go:embed templates/*
var templateFS embed.FS

// Feature describes an installable feature for abox init.
type Feature struct {
	Name    string            // Display name
	Desc    string            // Short description for menu (optional)
	Scripts []string          // Template filenames to include (under templates/)
	Overlay map[string]string // overlay relative path -> template filename
	Domains []string          // Suggested domains for allowlist hints
}

var features = []Feature{
	{
		Name:    "Claude Code",
		Scripts: []string{"claude-code.sh"},
		Overlay: map[string]string{
			"etc/claude-code/managed-settings.json": "managed-settings.json",
		},
		Domains: []string{"api.anthropic.com", "platform.claude.com", "claude.ai"},
	},
	{
		Name:    "Docker",
		Scripts: []string{"docker.sh"},
		Domains: []string{"*.docker.io", "registry-1.docker.io", "production.cloudflare.docker.com"},
	},
	{
		Name:    "Node.js",
		Scripts: []string{"nodejs.sh"},
		Domains: []string{"deb.nodesource.com", "registry.npmjs.org"},
	},
	{
		Name:    "Go",
		Scripts: []string{"go.sh"},
		Domains: []string{"go.dev", "proxy.golang.org", "sum.golang.org"},
	},
	{
		Name:    "Rust",
		Scripts: []string{"rust.sh"},
		Domains: []string{"sh.rustup.rs", "static.rust-lang.org", "crates.io"},
	},
	{
		Name:    "Python tools (pip, venv)",
		Scripts: []string{"python.sh"},
		Domains: []string{"pypi.org", "files.pythonhosted.org"},
	},
	{
		Name:    "Java (OpenJDK 21)",
		Scripts: []string{"java.sh"},
	},
	{
		Name:    "GitHub CLI (gh)",
		Scripts: []string{"gh.sh"},
		Domains: []string{"github.com", "*.githubusercontent.com", "cli.github.com"},
	},
	{
		Name:    "Dev utilities",
		Desc:    "ripgrep, fd, jq, tmux, sqlite3",
		Scripts: []string{"dev-utilities.sh"},
	},
}
