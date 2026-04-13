# Claude Code Example

An abox instance configured for running [Claude Code](https://claude.ai/code) in an isolated environment.

## Setup

```bash
cd examples/claude
abox up
```

## What's Installed

- Docker and docker-compose
- Node.js and npm
- Python 3 with venv
- git and gh CLI
- Claude Code (`@anthropic-ai/claude-code`)

## Network Access

Only `api.anthropic.com` and `platform.claude.com` are allowed by default. Add domains to the allowlist as needed:

```bash
abox allowlist add claude github.com
abox allowlist add claude '*.githubusercontent.com'
```

## Usage

```bash
abox ssh claude
claude  # Start Claude Code
```
