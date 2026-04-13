# Shell Completion

abox includes built-in shell completion for bash, zsh, and fish. Completions include commands, flags, and instance names.

## Bash

Create the completion directory if it doesn't exist, then generate the completion script:

```bash
mkdir -p ~/.bash_completion.d
abox completion bash > ~/.bash_completion.d/abox
```

Add to your `~/.bashrc`:

```bash
for f in ~/.bash_completion.d/*; do
    [ -f "$f" ] && source "$f"
done
```

Reload your shell or run `source ~/.bashrc`.

## Zsh

Generate the completion script to a directory in your `$fpath`:

```bash
abox completion zsh > "${fpath[1]}/_abox"
```

Or use a custom directory:

```bash
mkdir -p ~/.zsh/completions
abox completion zsh > ~/.zsh/completions/_abox
```

If using a custom directory, add it to your `~/.zshrc` before `compinit`:

```zsh
fpath=(~/.zsh/completions $fpath)
autoload -Uz compinit && compinit
```

## Fish

```bash
abox completion fish > ~/.config/fish/completions/abox.fish
```

Fish automatically loads completions from this directory.

## Next Steps

- [Quickstart Guide](quickstart.md) - Get started with abox
