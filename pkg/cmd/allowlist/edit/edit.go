// Package edit provides the allowlist edit command.
package edit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/validation"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// modTime wraps time.Time for allowlist modification time tracking.
type modTime time.Time

// errAborted signals the user chose to abort the edit.
var errAborted = errors.New("edit aborted")

// validationError represents an error on a specific line of the allowlist file.
type validationError struct {
	Line    int
	Content string
	Err     string
}

// Options holds the command options.
type Options struct {
	Factory  *factory.Factory
	NoReload bool
	Name     string
}

// NewCmdEdit creates a new allowlist edit command.
func NewCmdEdit(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "edit <instance>",
		Short: "Edit the allowlist file in your editor",
		Long:  `Opens the allowlist file in your preferred editor ($VISUAL, $EDITOR, or nano/vi).`,
		Example: `  abox allowlist edit dev                  # Open in $EDITOR
  abox allowlist edit dev --no-reload      # Edit without reloading filters`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runEdit(opts, args[0])
		},
	}

	cmd.Flags().BoolVar(&opts.NoReload, "no-reload", false, "Skip triggering filter reload after save")

	return cmd
}

func runEdit(opts *Options, name string) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	paths, err := config.GetPaths(name)
	if err != nil {
		return fmt.Errorf("failed to get paths: %w", err)
	}

	editor, err := getEditor()
	if err != nil {
		return err
	}

	origMtime, err := ensureAllowlistFile(paths.Allowlist)
	if err != nil {
		return err
	}

	// Create temp file in same directory for atomic rename
	tempFile, err := createTempCopy(paths.Allowlist)
	if err != nil {
		return err
	}
	defer os.Remove(tempFile) // Clean up on error

	w := opts.Factory.IO.Out
	if err := editUntilValid(opts, editor, tempFile, w); err != nil {
		if errors.Is(err, errAborted) {
			return nil
		}
		return err
	}

	// Check if content actually changed
	equal, err := filesEqual(paths.Allowlist, tempFile)
	if err != nil {
		return fmt.Errorf("failed to compare files: %w", err)
	}
	if equal {
		fmt.Fprintln(w, "No changes made")
		return nil
	}

	if err := handleConflict(paths.Allowlist, tempFile, editor, origMtime, w); err != nil {
		if errors.Is(err, errAborted) {
			return nil
		}
		return err
	}

	return saveAndReload(opts, paths, name, tempFile, w)
}

// ensureAllowlistFile creates the allowlist file if it doesn't exist,
// validates it's not a symlink, and returns its modification time.
func ensureAllowlistFile(path string) (modTime, error) {
	origInfo, err := os.Lstat(path)
	if os.IsNotExist(err) {
		file, err := allowlist.OpenFileNoFollow(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return modTime{}, fmt.Errorf("failed to create allowlist file: %w", err)
		}
		_, writeErr := file.WriteString("# Domain allowlist - one domain per line\n# Lines starting with # are comments\n# Wildcard prefix *.domain.com is supported\n\n")
		file.Close()
		if writeErr != nil {
			return modTime{}, fmt.Errorf("failed to write allowlist file: %w", writeErr)
		}
		origInfo, err = os.Lstat(path)
		if err != nil {
			return modTime{}, fmt.Errorf("failed to stat allowlist file: %w", err)
		}
	} else if err != nil {
		return modTime{}, fmt.Errorf("failed to stat allowlist file: %w", err)
	}
	if origInfo.Mode()&os.ModeSymlink != 0 {
		return modTime{}, fmt.Errorf("allowlist path is a symlink (security risk): %s", path)
	}
	return modTime(origInfo.ModTime()), nil
}

// editUntilValid launches the editor in a loop until the file passes validation
// or the user aborts.
func editUntilValid(opts *Options, editor, tempFile string, w io.Writer) error {
	for {
		if err := launchEditor(editor, tempFile); err != nil {
			return fmt.Errorf("editor failed: %w", err)
		}

		validationErrors := validateAllowlist(tempFile)
		if len(validationErrors) == 0 {
			return nil
		}

		printValidationErrors(w, validationErrors)
		if !opts.Factory.Prompter.ConfirmWithDefault("Re-edit? [Y/n] ", true) {
			fmt.Fprintln(w, "Aborting edit")
			return errAborted
		}
	}
}

// handleConflict checks for and resolves conflicts if the allowlist was modified
// during the edit session.
func handleConflict(allowlistPath, tempFile, editor string, origMtime modTime, w io.Writer) error {
	currentInfo, err := os.Lstat(allowlistPath)
	if err != nil {
		return fmt.Errorf("failed to check allowlist: %w", err)
	}
	if currentInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("allowlist path is a symlink (security risk): %s", allowlistPath)
	}

	if currentInfo.ModTime().Equal(time.Time(origMtime)) {
		return nil
	}

	fmt.Fprintln(w, "Conflict: allowlist was modified while you were editing.")
	fmt.Fprintln(w)
	showDiff(w, allowlistPath, tempFile)

	return resolveConflict(allowlistPath, tempFile, editor, w)
}

func resolveConflict(allowlistPath, tempFile, editor string, w io.Writer) error {
	for {
		fmt.Fprint(w, "[O]verwrite with your changes / [K]eep original / [R]e-edit: ")
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return nil //nolint:nilerr // EOF on stdin (e.g. pipe closed) exits gracefully
		}
		response = strings.TrimSpace(strings.ToLower(response))

		switch response {
		case "o", "overwrite":
			return nil
		case "k", "keep":
			fmt.Fprintln(w, "Keeping original file")
			return errAborted
		case "r", "re-edit", "reedit":
			if err := launchEditor(editor, tempFile); err != nil {
				return fmt.Errorf("editor failed: %w", err)
			}
			validationErrors := validateAllowlist(tempFile)
			if len(validationErrors) > 0 {
				printValidationErrors(w, validationErrors)
				continue
			}
			equal, err := filesEqual(allowlistPath, tempFile)
			if err != nil {
				return fmt.Errorf("failed to compare files: %w", err)
			}
			if equal {
				fmt.Fprintln(w, "No changes made")
				return errAborted
			}
			return nil
		default:
			fmt.Fprintln(w, "Please enter O, K, or R")
		}
	}
}

func saveAndReload(opts *Options, paths *config.Paths, name, tempFile string, w io.Writer) error {
	if err := os.Rename(tempFile, paths.Allowlist); err != nil {
		if err := copyFile(tempFile, paths.Allowlist); err != nil {
			return fmt.Errorf("failed to save allowlist: %w", err)
		}
	}

	domainCount := countDomains(paths.Allowlist)
	fmt.Fprintf(w, "Allowlist updated (%d domains)\n", domainCount)

	logging.AuditInstance(name, logging.ActionAllowlistEdit,
		"domains", domainCount,
	)

	if !opts.NoReload {
		if err := triggerReload(opts.Factory, name, w); err != nil {
			fmt.Fprintf(w, "Note: %v\n", err)
		}
	}

	return nil
}

func printValidationErrors(w io.Writer, errs []validationError) {
	fmt.Fprintln(w, "Validation errors:")
	for _, ve := range errs {
		fmt.Fprintf(w, "  Line %d: %q - %s\n", ve.Line, ve.Content, ve.Err)
	}
}

// getEditor returns the user's preferred editor.
func getEditor() (string, error) {
	// Try $VISUAL first
	if editor := os.Getenv("VISUAL"); editor != "" {
		return editor, nil
	}

	// Try $EDITOR
	if editor := os.Getenv("EDITOR"); editor != "" {
		return editor, nil
	}

	// Try common editors
	for _, editor := range []string{"nano", "vi", "vim"} {
		if path, err := exec.LookPath(editor); err == nil {
			return path, nil
		}
	}

	return "", errors.New("no editor found: set $VISUAL or $EDITOR environment variable")
}

// createTempCopy creates a temporary copy of the file in the same directory.
// Uses O_EXCL to prevent race conditions where an attacker creates a symlink
// at the predicted temp path between path generation and file creation.
func createTempCopy(src string) (string, error) {
	dir := filepath.Dir(src)
	base := filepath.Base(src)

	// Open source file with O_NOFOLLOW to prevent symlink attacks
	srcFile, err := allowlist.OpenFileNoFollow(src, os.O_RDONLY, 0)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Try a few times with different random suffixes in case of collision
	var tempPath string
	var dstFile *os.File
	for range 3 {
		suffix := rand.Int64() //nolint:gosec // temp file suffix doesn't need crypto randomness
		tempPath = filepath.Join(dir, fmt.Sprintf("%s.edit.%d.tmp", base, suffix))

		// Use O_EXCL to fail if file already exists (prevents symlink race)
		// O_NOFOLLOW prevents following symlinks at the temp path
		dstFile, err = allowlist.OpenFileNoFollow(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return "", fmt.Errorf("failed to create temp file: %w", err)
		}
	}
	if dstFile == nil {
		return "", errors.New("failed to create temp file after retries")
	}

	_, copyErr := io.Copy(dstFile, srcFile)
	closeErr := dstFile.Close()
	if copyErr != nil {
		os.Remove(tempPath)
		return "", fmt.Errorf("failed to copy to temp file: %w", copyErr)
	}
	if closeErr != nil {
		os.Remove(tempPath)
		return "", fmt.Errorf("failed to close temp file: %w", closeErr)
	}

	return tempPath, nil
}

// copyFile copies a file from src to dst with symlink protection.
// Used for the rename fallback when atomic rename fails (cross-filesystem).
func copyFile(src, dst string) error {
	srcFile, err := allowlist.OpenFileNoFollow(src, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Use O_NOFOLLOW to prevent following symlinks at destination
	dstFile, err := allowlist.OpenFileNoFollow(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		dstFile.Close()
		return err
	}
	if err := dstFile.Sync(); err != nil {
		dstFile.Close()
		return err
	}
	return dstFile.Close()
}

// filesEqual returns true if the two files have identical content.
// Uses hash comparison to avoid loading entire files into memory.
func filesEqual(path1, path2 string) (bool, error) {
	hash1, err := hashFile(path1)
	if err != nil {
		return false, err
	}
	hash2, err := hashFile(path2)
	if err != nil {
		return false, err
	}
	return bytes.Equal(hash1, hash2), nil
}

// hashFile returns the SHA-256 hash of the file content.
func hashFile(path string) ([]byte, error) {
	f, err := allowlist.OpenFileNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// validateAllowlist validates the allowlist file and returns any errors.
func validateAllowlist(path string) []validationError {
	file, err := allowlist.OpenFileNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return []validationError{{Line: 0, Content: "", Err: err.Error()}}
	}
	defer file.Close()

	var errs []validationError
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle wildcard syntax: *.domain.com -> domain.com for validation
		domainToValidate := strings.TrimPrefix(line, "*.")

		if err := validation.ValidateDomain(domainToValidate); err != nil {
			errs = append(errs, validationError{
				Line:    lineNum,
				Content: line,
				Err:     err.Error(),
			})
		}
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, validationError{Line: 0, Content: "", Err: err.Error()})
	}

	return errs
}

// launchEditor opens the file in the user's editor.
func launchEditor(editor, path string) error {
	cmd := exec.Command(editor, path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// showDiff displays a unified diff between the original and edited files.
func showDiff(w io.Writer, original, edited string) {
	// Try to use diff command
	cmd := exec.Command("diff", "-u", "--label", "original", "--label", "your-edits", original, edited)
	cmd.Stdout = w
	cmd.Stderr = w
	_ = cmd.Run() // Ignore error (diff returns 1 if files differ)
	fmt.Fprintln(w)
}

// countDomains counts the number of valid domains in the allowlist.
func countDomains(path string) int {
	file, err := allowlist.OpenFileNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return 0
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}

// triggerReload triggers a reload of both DNS and HTTP filters.
func triggerReload(f *factory.Factory, name string, w io.Writer) error {
	var dnsErr, httpErr error

	dnsErr = f.WithAllowlistClient(name, func(ctx context.Context, client rpc.AllowlistClient) error {
		_, err := client.Reload(ctx, &rpc.Empty{})
		return err
	})

	httpErr = f.WithHTTPAllowlistClient(name, func(ctx context.Context, client rpc.AllowlistClient) error {
		_, err := client.Reload(ctx, &rpc.Empty{})
		return err
	})

	if dnsErr == nil {
		fmt.Fprintln(w, "Reloaded DNS filter")
	}
	if httpErr == nil {
		fmt.Fprintln(w, "Reloaded HTTP filter")
	}

	if dnsErr != nil && httpErr != nil {
		return errors.New("filters not running (start the instance to apply changes)")
	}

	return nil
}
