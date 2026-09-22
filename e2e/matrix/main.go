// Program matrix runs e2e tests across multiple base images with a single
// privilege helper, then prints a compatibility report.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/internal/backend"
	// The backends self-register via blank imports in the OS-gated
	// backends_*.go files (mirroring pkg/cmd/root); the matrix needs the registry
	// populated to enumerate backends and probe IsAvailable() per host. Keeping
	// the libvirt (linux-only) import out of this file lets the matrix cross-compile.
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/images"
	"github.com/sandialabs/abox/internal/natsort"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

type result struct {
	Backend  string
	Base     string
	Passed   bool
	Duration time.Duration
	LogFile  string
}

// backendOutcome records the per-backend result: either it was skipped
// (unavailable on this host) or it ran the base loop and produced base results.
type backendOutcome struct {
	Backend     string
	Skipped     bool
	SkipReason  string
	BaseResults []result
}

func main() {
	var autoPull bool
	var short bool
	var timeout string
	var timeoutSet bool
	var runFilter string
	var backendsFlag []string

	rootCmd := &cobra.Command{
		Use:   "matrix [bases...]",
		Short: "Run e2e tests across multiple backends and base images",
		Long: `Run e2e tests across a 2-D matrix of backends × base images with a single
privilege helper, then print a compatibility report.

The suite iterates each selected backend and, for the backends available on this
host, runs the base-image loop underneath. Backends that report IsAvailable()==false
are reported as SKIP rather than failing the run.

Without --backends, all registered backends are considered (each SKIPPED when
unavailable). Without base arguments, all locally downloaded base images are tested.

Examples:
  go run ./e2e/matrix/                            # all backends × all downloaded bases
  go run ./e2e/matrix/ ubuntu-24.04 debian-12     # all backends × specific bases
  go run ./e2e/matrix/ --backends libvirt          # only the libvirt backend
  go run ./e2e/matrix/ --backends libvirt,vmware   # both backends
  go run ./e2e/matrix/ --auto-pull                 # pull all known bases, then test all
  go run ./e2e/matrix/ --auto-pull almalinux-9     # pull if needed, then test
  go run ./e2e/matrix/ --timeout 45m               # custom per-base timeout
  go run ./e2e/matrix/ --short                     # smoke tests only (~2 min per base)
  go run ./e2e/matrix/ --run TestMonitorEventTypes  # run only matching tests`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			timeoutSet = cmd.Flags().Changed("timeout")
			return run(args, backendsFlag, autoPull, short, timeout, timeoutSet, runFilter)
		},
	}

	rootCmd.Flags().StringSliceVar(&backendsFlag, "backends", nil, "Backends to test (comma-separated). Default: all registered backends (unavailable ones are SKIPPED). Overrides ABOX_BACKEND.")
	rootCmd.Flags().BoolVar(&autoPull, "auto-pull", false, "Pull missing base images before testing")
	rootCmd.Flags().BoolVar(&short, "short", false, "Smoke tests only (lifecycle + up/down)")
	rootCmd.Flags().StringVar(&timeout, "timeout", "45m", "Per-base test timeout (passed to go test -timeout)")
	rootCmd.Flags().StringVar(&runFilter, "run", "", "Test filter regexp (passed to go test -run)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// resolveBackends returns the ordered list of backend names to iterate.
// Precedence: explicit --backends flag, then ABOX_BACKEND, then all registered
// backends. Unknown names (not registered) are rejected up front so a typo fails
// fast rather than silently SKIPping.
func resolveBackends(backendsFlag []string) ([]string, error) {
	var names []string
	switch {
	case len(backendsFlag) > 0:
		names = backendsFlag
	case os.Getenv(factory.EnvBackend) != "":
		names = []string{os.Getenv(factory.EnvBackend)}
	default:
		names = backend.RegisteredNames()
	}

	for _, n := range names {
		if !backend.IsRegistered(n) {
			return nil, fmt.Errorf("unknown backend: %s", n)
		}
	}
	return names, nil
}

func run(filterBases, backendsFlag []string, autoPull, short bool, timeout string, timeoutSet bool, runFilter string) error {
	startTime := time.Now()

	// Determine the backend dimension up front so a typo fails fast.
	backends, err := resolveBackends(backendsFlag)
	if err != nil {
		return err
	}
	if len(backends) == 0 {
		return errors.New("no backends registered")
	}

	// Build abox binary.
	fmt.Println("Building abox...")
	build := exec.Command("go", "build", "-o", "abox", "./cmd/abox")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("failed to build abox: %w", err)
	}

	aboxBin, err := filepath.Abs("./abox")
	if err != nil {
		return fmt.Errorf("failed to resolve abox path: %w", err)
	}

	// Determine base list.
	var bases []string
	if autoPull {
		bases, err = resolveAutoPull(aboxBin, filterBases)
	} else {
		bases, err = resolveDownloaded(filterBases)
	}
	if err != nil {
		return err
	}

	if len(bases) == 0 {
		return errors.New("no base images found; use --auto-pull to download images")
	}

	sort.Slice(bases, func(i, j int) bool {
		return natsort.Less(bases[i], bases[j])
	})

	// Default to shorter timeout in short mode when not explicitly set.
	if short && !timeoutSet {
		timeout = "7m"
	}

	mode := ""
	if short {
		mode = " (smoke)"
	}
	fmt.Printf("Testing %d backend(s): %s\n", len(backends), strings.Join(backends, ", "))
	fmt.Printf("Testing %d base(s)%s: %s\n\n", len(bases), mode, strings.Join(bases, ", "))

	// Create results directory.
	logDir := filepath.Join("e2e-results", time.Now().Format("2006-01-02_150405"))
	if err := os.MkdirAll(logDir, 0o755); err != nil { //nolint:gosec // results dir needs 0o755
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	// Start privilege helper (single sudo prompt).
	helperCleanup, env, err := startHelper(aboxBin)
	if err != nil {
		return fmt.Errorf("failed to start privilege helper: %w", err)
	}
	defer helperCleanup()

	// Iterate backends (outer) × bases (inner). Backends unavailable on this host
	// are SKIPPED rather than failed, so a libvirt-only host still passes when the
	// vmware backend is in the matrix but not installed.
	var outcomes []backendOutcome
	for bi, backendName := range backends {
		fmt.Printf("=== backend [%d/%d] %s ===\n", bi+1, len(backends), backendName)

		if reason := backendUnavailableReason(backendName); reason != "" {
			fmt.Printf("  SKIP: %s\n\n", reason)
			outcomes = append(outcomes, backendOutcome{
				Backend:    backendName,
				Skipped:    true,
				SkipReason: reason,
			})
			continue
		}

		var baseResults []result
		for i, base := range bases {
			fmt.Printf("[%s %d/%d] Testing %s ...\n", backendName, i+1, len(bases), base)

			r := runTests(backendName, base, logDir, timeout, short, runFilter, env)
			baseResults = append(baseResults, r)

			if r.Passed {
				fmt.Printf("  PASS (%s)\n\n", formatDuration(r.Duration))
			} else {
				fmt.Printf("  FAIL (%s)\n", formatDuration(r.Duration))
				printTail(r.LogFile, 20)
				fmt.Println()
			}
		}
		outcomes = append(outcomes, backendOutcome{
			Backend:     backendName,
			BaseResults: baseResults,
		})
	}

	// Print report.
	totalDuration := time.Since(startTime)
	printReport(outcomes, logDir, totalDuration)

	// Exit non-zero if any (backend, base) cell failed. Skipped backends do not
	// fail the run.
	for _, o := range outcomes {
		for _, r := range o.BaseResults {
			if !r.Passed {
				return errors.New("some cells failed")
			}
		}
	}
	return nil
}

// backendUnavailableReason returns a human-readable reason the backend cannot be
// tested on this host, or "" when it is available. It defers to the backend's own
// IsAvailable() (via backend.Get), mirroring the e2e harness's capability skip.
func backendUnavailableReason(name string) string {
	if _, err := backend.Get(name); err != nil {
		return err.Error()
	}
	return ""
}

// resolveAutoPull fetches all known images, pulls any that are missing, and
// returns the list filtered by filterBases (or all if filterBases is empty).
func resolveAutoPull(aboxBin string, filterBases []string) ([]string, error) {
	allImages, err := images.FetchAll(context.Background(), false)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image list: %w", err)
	}

	// Filter to requested bases if specified.
	var targets []images.ImageInfo
	if len(filterBases) > 0 {
		wanted := make(map[string]bool, len(filterBases))
		for _, b := range filterBases {
			wanted[b] = true
		}
		for _, img := range allImages {
			if wanted[img.Name] {
				targets = append(targets, img)
			}
		}
		// Check for unknown bases.
		for _, b := range filterBases {
			found := false
			for _, img := range allImages {
				if img.Name == b {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("unknown base image: %s", b)
			}
		}
	} else {
		targets = allImages
	}

	// Pull any that aren't downloaded.
	for _, img := range targets {
		if !isBaseDownloaded(img.Name) {
			fmt.Printf("Pulling %s ...\n", img.Name)
			if err := pullBase(aboxBin, img.Name); err != nil {
				return nil, fmt.Errorf("failed to pull %s: %w", img.Name, err)
			}
		}
	}

	var names []string
	for _, img := range targets {
		names = append(names, img.Name)
	}
	return names, nil
}

// resolveDownloaded returns locally downloaded bases, filtered by filterBases.
func resolveDownloaded(filterBases []string) ([]string, error) {
	downloaded := discoverDownloadedBases()

	if len(filterBases) == 0 {
		return downloaded, nil
	}

	available := make(map[string]bool, len(downloaded))
	for _, b := range downloaded {
		available[b] = true
	}

	var result []string
	for _, b := range filterBases {
		if !available[b] {
			return nil, fmt.Errorf("base image %s not found locally; use --auto-pull to download", b)
		}
		result = append(result, b)
	}
	return result, nil
}

// baseSearchDirs returns the directories to search for downloaded base images,
// backend-aware and consistent with the e2e helper side (baseImageDirs). It
// includes every registered backend's StorageDir()/base (so both libvirt and
// vmware bases are found regardless of which backend a run selects), the
// backend-neutral user download cache (where `abox base pull` writes), and the
// legacy root-owned LibvirtImagesDir for backward compatibility.
func baseSearchDirs() []string {
	seen := make(map[string]bool)
	var dirs []string
	add := func(d string) {
		if d == "" || seen[d] {
			return
		}
		seen[d] = true
		dirs = append(dirs, d)
	}

	// Backend-managed storage for every registered backend.
	for _, name := range backend.RegisteredNames() {
		if b, err := backend.Get(name); err == nil {
			add(filepath.Join(b.StorageDir(), "base"))
		}
	}

	// Backend-neutral user download cache.
	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, ".local", "share", "abox", "base"))
	}

	// Legacy root-owned libvirt image location (may still hold bases).
	add(filepath.Join(config.LibvirtImagesDir, "base"))

	return dirs
}

// matrixBaseImageExts lists on-disk base-image extensions to probe, in priority
// order. Most backends keep the downloaded qcow2; the vfkit (macOS) backend uses
// raw (Apple Virtualization.framework cannot read qcow2). Mirrors baseImageExts
// in e2e/helpers_test.go so matrix discovery stays symmetric with the helper side.
var matrixBaseImageExts = []string{".qcow2", ".raw"}

// discoverDownloadedBases scans all base image directories for base image files
// (any extension in matrixBaseImageExts).
func discoverDownloadedBases() []string {
	seen := make(map[string]bool)
	var bases []string

	for _, dir := range baseSearchDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // directory may not exist
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			for _, ext := range matrixBaseImageExts {
				if !strings.HasSuffix(name, ext) {
					continue
				}
				base := strings.TrimSuffix(name, ext)
				if !seen[base] {
					seen[base] = true
					bases = append(bases, base)
				}
				break
			}
		}
	}

	return bases
}

// isBaseDownloaded checks if a base image exists locally in any backend-aware or
// backend-neutral base directory (see baseSearchDirs), for any extension in
// matrixBaseImageExts.
func isBaseDownloaded(name string) bool {
	for _, dir := range baseSearchDirs() {
		for _, ext := range matrixBaseImageExts {
			if _, err := os.Stat(filepath.Join(dir, name+ext)); err == nil {
				return true
			}
		}
	}
	return false
}

// pullBase shells out to abox base pull to download a base image.
func pullBase(aboxBin, name string) error {
	cmd := exec.Command(aboxBin, "base", "pull", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// startHelper starts a shared privilege helper and returns a cleanup function
// and the environment variables to pass to subprocesses.
func startHelper(aboxBin string) (cleanup func(), env []string, err error) {
	// Generate auth token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Generate socket path.
	socketDir := config.RuntimeDirOr(os.TempDir())
	socket := filepath.Join(socketDir, fmt.Sprintf("abox-matrix-%d.sock", os.Getpid()))
	os.Remove(socket)

	// Build command with sudo.
	cmd := exec.Command("sudo", aboxBin, "privilege-helper",
		"--socket", socket,
		"--allowed-uid", strconv.Itoa(os.Getuid()))

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	cmd.Stderr = os.Stderr

	fmt.Println("Starting shared privilege helper (single sudo prompt for all tests)...")

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("failed to start helper: %w", err)
	}

	// Send token via stdin.
	if _, err := io.WriteString(stdin, token+"\n"); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, nil, fmt.Errorf("failed to send token: %w", err)
	}
	stdin.Close()

	// Wait for socket to appear.
	if err := waitForSocket(socket, 60*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, nil, err
	}

	fmt.Println("Shared privilege helper started successfully")

	// Build env for subprocesses: inherit current env plus helper vars.
	env = os.Environ()
	env = append(env,
		factory.EnvPrivilegeSocket+"="+socket,
		factory.EnvPrivilegeToken+"="+token,
	)

	cleanup = func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		os.Remove(socket)
	}

	return cleanup, env, nil
}

// waitForSocket waits for a socket file to appear.
func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for socket %s", path)
}

// runTests executes go test for a single (backend, base) cell and returns the
// result. The selected backend is passed to the subprocess via ABOX_BACKEND so
// the e2e harness (backendUnderTest) exercises that backend. Output streams to a
// per-cell log file only; the caller prints progress lines.
func runTests(backendName, base, logDir, timeout string, short bool, runFilter string, env []string) result {
	logFile := filepath.Join(logDir, backendName+"_"+base+".log")

	f, err := os.Create(logFile)
	if err != nil {
		return result{Backend: backendName, Base: base, LogFile: logFile}
	}
	defer f.Close()

	start := time.Now()

	// -count=1 disables go's test result cache: e2e outcomes depend on external
	// state (installed tools, a running backend, base images, network) that the
	// build cache cannot observe, so a cached result could hide real changes.
	args := []string{"test", "-tags=e2e", "-v", "-count=1", "-timeout", timeout}
	if short {
		args = append(args, "-short", "-failfast")
	}
	if runFilter != "" {
		args = append(args, "-run", runFilter)
	}
	args = append(args, "./e2e")
	cmd := exec.Command("go", args...)
	cmd.Env = append(env, "ABOX_E2E_BASE="+base, factory.EnvBackend+"="+backendName)
	cmd.Stdout = f
	cmd.Stderr = f

	err = cmd.Run()
	duration := time.Since(start)

	return result{
		Backend:  backendName,
		Base:     base,
		Passed:   err == nil,
		Duration: duration,
		LogFile:  logFile,
	}
}

// printTail prints the last n lines of a file to stderr.
// Reads only the tail of the file to avoid loading large logs into memory.
func printTail(path string, n int) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	// Read backwards from end of file to find the last n newlines.
	// Use a chunk size that's generous enough for typical log lines.
	const chunkSize = 8192
	info, err := f.Stat()
	if err != nil {
		return
	}
	size := info.Size()
	if size == 0 {
		return
	}

	// Read enough from the end to capture n lines.
	offset := max(size-chunkSize, 0)

	buf := make([]byte, size-offset)
	if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
		return
	}

	// Split into lines and take the last n.
	text := strings.TrimRight(string(buf), "\n")
	lines := strings.Split(text, "\n")

	// If we didn't read from the start and still have more than n lines, take last n.
	// If we read a partial chunk and got exactly n or fewer, that's fine.
	start := 0
	if len(lines) > n {
		start = len(lines) - n
	} else if offset > 0 {
		// We may have a partial first line from mid-file; skip it.
		start = 1
		if len(lines)-1 > n {
			start = len(lines) - n
		}
	}

	fmt.Fprintf(os.Stderr, "  --- last %d lines of %s ---\n", n, path)
	for _, line := range lines[start:] {
		fmt.Fprintf(os.Stderr, "  %s\n", line)
	}
}

// printReport prints a 2-D backend × base summary and writes it to report.txt.
// Each available backend lists its per-base PASS/FAIL cells; unavailable backends
// are shown as a single SKIP line with the reason.
func printReport(outcomes []backendOutcome, logDir string, totalDuration time.Duration) {
	now := time.Now().Format("2006-01-02 15:04:05")

	var passed, failed, cells, skippedBackends int
	for _, o := range outcomes {
		if o.Skipped {
			skippedBackends++
			continue
		}
		for _, r := range o.BaseResults {
			cells++
			if r.Passed {
				passed++
			} else {
				failed++
			}
		}
	}

	// Column width for base names across all backends.
	maxBase := len("BASE")
	for _, o := range outcomes {
		for _, r := range o.BaseResults {
			if len(r.Base) > maxBase {
				maxBase = len(r.Base)
			}
		}
	}

	var b strings.Builder
	sep := strings.Repeat("═", 44+maxBase)

	fmt.Fprintf(&b, "%s\n", sep)
	fmt.Fprintf(&b, "  abox e2e compatibility report (backend × base)\n")
	fmt.Fprintf(&b, "  %s (%s total)\n", now, formatDuration(totalDuration))
	fmt.Fprintf(&b, "%s\n", sep)

	for _, o := range outcomes {
		fmt.Fprintf(&b, "\nBACKEND: %s\n", o.Backend)
		if o.Skipped {
			fmt.Fprintf(&b, "  SKIP (unavailable): %s\n", o.SkipReason)
			continue
		}
		fmt.Fprintf(&b, "  %-*s  %-6s  %s\n", maxBase, "BASE", "STATUS", "DURATION")
		for _, r := range o.BaseResults {
			status := "PASS"
			if !r.Passed {
				status = "FAIL"
			}
			fmt.Fprintf(&b, "  %-*s  %-6s  %s\n", maxBase, r.Base, status, formatDuration(r.Duration))
		}
	}

	fmt.Fprintf(&b, "\n%d/%d cells passed, %d/%d failed", passed, cells, failed, cells)
	if skippedBackends > 0 {
		fmt.Fprintf(&b, "; %d backend(s) skipped (unavailable)", skippedBackends)
	}
	fmt.Fprintf(&b, "\nResults: %s/\n", logDir)

	report := b.String()
	fmt.Print("\n" + report)

	// Save report to file.
	reportPath := filepath.Join(logDir, "report.txt")
	if err := os.WriteFile(reportPath, []byte(report), 0o644); err != nil { //nolint:gosec // test report file
		fmt.Fprintf(os.Stderr, "warning: failed to write report: %v\n", err)
	}
}

// formatDuration formats a duration as "Xm Ys" or "Xs" for short durations.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm %02ds", m, s)
}
