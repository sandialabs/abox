package pull

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/images"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/tui"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the base pull command.
type Options struct {
	Factory *factory.Factory
	Names   []string
}

// NewCmdPull creates a new base pull command.
func NewCmdPull(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "pull [image...]",
		Short: "Download a base image",
		Example: `  abox base pull ubuntu-24.04              # Download a specific image
  abox base pull                           # Interactive image picker`,
		Long: `Download one or more base images to the local cache.

If no image is specified, an interactive picker will be shown.

Images are stored in ~/.local/share/abox/base/ and will be copied to
the libvirt images directory when creating an instance.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Names = args
			if runF != nil {
				return runF(opts)
			}
			ctx := cmd.Context()
			if len(args) == 0 {
				return runPullInteractive(ctx, f)
			}
			var errs []error
			for _, name := range args {
				if err := runPull(ctx, f, name); err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", name, err))
				}
			}
			return errors.Join(errs...)
		},
	}

	return cmd
}

// ---------------------------------------------------------------------------
// Image lookup / picker (pre-TUI)
// ---------------------------------------------------------------------------

// pickImage shows an interactive picker and returns the selected image.
func pickImage(ctx context.Context, w io.Writer, prompter cmdutil.Prompter) (*images.ImageInfo, error) {
	fmt.Fprintln(w, "Fetching available images...")

	allImages, err := images.FetchAll(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch images: %w", err)
	}

	paths, err := config.GetPaths("")
	if err != nil {
		return nil, err
	}

	grouped := images.GroupByProvider(allImages)
	providerOrder := images.ProviderOrder()

	groups := make(map[string][]cmdutil.Option)
	groupOrder := make([]string, 0, len(providerOrder))
	var flatImages []images.ImageInfo

	for _, provider := range providerOrder {
		providerImages := grouped[provider]
		if len(providerImages) == 0 {
			continue
		}

		displayName := images.ProviderDisplayName(provider)
		groupOrder = append(groupOrder, displayName)

		for _, img := range providerImages {
			status := ""
			imagePath := filepath.Join(paths.UserBaseImages, img.Name+".qcow2")
			if _, err := os.Stat(imagePath); err == nil {
				status = "[downloaded]"
			}

			description := img.Description
			if status != "" {
				description = fmt.Sprintf("%-35s %s", img.Description, status)
			}

			groups[displayName] = append(groups[displayName], cmdutil.Option{
				Label:       img.Name,
				Description: description,
			})
			flatImages = append(flatImages, img)
		}
	}

	selection := prompter.SelectWithGroups("Available base images:", groups, groupOrder)
	if selection < 0 {
		return nil, errors.New("no image selected")
	}

	return &flatImages[selection], nil
}

// showAvailable prints available images after a lookup failure.
func showAvailable(ctx context.Context, w io.Writer) {
	fmt.Fprintln(w, "\nFetching available images...")
	allImages, fetchErr := images.FetchAll(ctx, false)
	if fetchErr != nil {
		return
	}
	fmt.Fprintln(w, "\nAvailable images:")
	for _, img := range allImages {
		fmt.Fprintf(w, "  %-15s %s\n", img.Name, img.Description)
	}
}

// runPullInteractive shows an interactive picker, then pulls the image.
func runPullInteractive(ctx context.Context, f *factory.Factory) error {
	w := f.IO.Out
	img, err := pickImage(ctx, w, f.Prompter)
	if err != nil {
		return err
	}
	return runPullImage(ctx, f, img)
}

// runPull looks up an image by name, then pulls it.
func runPull(ctx context.Context, f *factory.Factory, name string) error {
	w := f.IO.Out
	img, err := images.FindByName(ctx, name)
	if err != nil {
		fmt.Fprintf(w, "Unknown image: %s\n", name)
		showAvailable(ctx, w)
		return err
	}
	return runPullImage(ctx, f, img)
}

// runPullImage checks existence, then dispatches to TUI or plain path.
func runPullImage(ctx context.Context, f *factory.Factory, img *images.ImageInfo) error {
	w := f.IO.Out

	paths, err := config.GetPaths("")
	if err != nil {
		return err
	}

	destPath := filepath.Join(paths.UserBaseImages, img.Name+".qcow2")

	// Check if already exists
	if _, err := os.Stat(destPath); err == nil {
		fmt.Fprintf(w, "Image %s already exists at %s\n", img.Name, destPath)
		fmt.Fprintln(w, "Delete it first if you want to re-download.")
		return nil
	}

	// Ensure base directory exists
	if err := os.MkdirAll(paths.UserBaseImages, 0o755); err != nil { //nolint:gosec // image dir needs 0o755 for user access
		return fmt.Errorf("failed to create directory %s: %w", paths.UserBaseImages, err)
	}

	if f.IO.IsTerminal() {
		return runPullImageTUI(ctx, f, img, destPath)
	}
	return runPullImagePlain(ctx, f, img, destPath)
}

// ---------------------------------------------------------------------------
// Plain text path (non-TTY or pipe)
// ---------------------------------------------------------------------------

// plainProgressNotifier embeds NoopNotifier and overrides PhaseProgress to
// write inline \r progress to the writer.
type plainProgressNotifier struct {
	tui.NoopNotifier
	w io.Writer
}

func (n *plainProgressNotifier) PhaseProgress(_ int, pct float64, detail string) {
	fmt.Fprintf(n.w, "\r  %.1f%% %s", pct*100, detail)
}

func runPullImagePlain(ctx context.Context, f *factory.Factory, img *images.ImageInfo, destPath string) error {
	w := f.IO.Out
	notify := &plainProgressNotifier{w: w}

	fmt.Fprintf(w, "Downloading %s...\n", img.Name)
	fmt.Fprintf(w, "URL: %s\n", img.URL)

	computedHash, err := downloadImage(ctx, img, destPath+".tmp", notify)
	if err != nil {
		return err
	}
	defer os.Remove(destPath + ".tmp")
	fmt.Fprintln(w) // newline after \r progress

	if err := verifyChecksum(w, img, computedHash); err != nil {
		os.Remove(destPath + ".tmp")
		return err
	}

	if err := convertImage(w, destPath+".tmp", destPath); err != nil {
		return err
	}

	fmt.Fprintf(w, "\nImage saved to: %s\n", destPath)
	fmt.Fprintf(w, "Create: abox create <name> --base %s\n", img.Name)

	logging.Audit(logging.ActionBasePull, "action", logging.ActionBasePull, "image", img.Name)
	return nil
}

// ---------------------------------------------------------------------------
// TUI path
// ---------------------------------------------------------------------------

func runPullImageTUI(ctx context.Context, f *factory.Factory, img *images.ImageInfo, destPath string) error {
	steps := []tui.Step{
		{Name: "Download image"},
		{Name: "Verify checksum"},
		{Name: "Convert to qcow2"},
	}

	done := tui.DoneConfig{
		SuccessMsg: fmt.Sprintf("Image %q pulled!", img.Name),
		HintLines:  []string{"Create: abox create <name> --base " + img.Name},
	}

	return tui.Run("abox base pull: "+img.Name, steps, done, func(out io.Writer, errOut io.Writer, notify tui.PhaseNotifier) error {
		f.IO.SetOutputSplit(out, errOut)
		defer f.IO.RestoreOutput()
		old := logging.StderrWriter().Swap(errOut)
		defer logging.StderrWriter().Swap(old)

		// Phase 0: Download
		notify.PhaseStart(0)
		computedHash, err := downloadImage(ctx, img, destPath+".tmp", notify)
		if err != nil {
			notify.PhaseDone(0, err)
			return err
		}
		defer os.Remove(destPath + ".tmp")
		notify.PhaseDone(0, nil)

		// Phase 1: Verify checksum
		notify.PhaseStart(1)
		if err := verifyChecksum(out, img, computedHash); err != nil {
			notify.PhaseDone(1, err)
			os.Remove(destPath + ".tmp")
			return err
		}
		notify.PhaseDone(1, nil)

		// Phase 2: Convert
		notify.PhaseStart(2)
		if err := convertImage(out, destPath+".tmp", destPath); err != nil {
			notify.PhaseDone(2, err)
			return err
		}
		notify.PhaseDone(2, nil)

		logging.Audit(logging.ActionBasePull, "action", logging.ActionBasePull, "image", img.Name)
		return nil
	})
}

// ---------------------------------------------------------------------------
// Work helpers
// ---------------------------------------------------------------------------

// downloadImage downloads the image to destTmp, hashing as it goes.
// It calls notify.PhaseProgress(0, ...) with throttled updates for the
// download progress bar.
func downloadImage(ctx context.Context, img *images.ImageInfo, destTmp string, notify tui.PhaseNotifier) (string, error) {
	client := &http.Client{Timeout: 30 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, img.URL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download: HTTP %d", resp.StatusCode)
	}

	out, err := os.Create(destTmp)
	if err != nil {
		return "", err
	}

	var hasher hash.Hash
	switch img.HashAlgo {
	case "sha512":
		hasher = sha512.New()
	default:
		hasher = sha256.New()
	}

	downloaded, err := copyWithProgress(out, resp.Body, hasher, resp.ContentLength, notify)
	if err != nil {
		out.Close()
		os.Remove(destTmp)
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", fmt.Errorf("failed to close download file: %w", err)
	}

	// Final 100% progress
	if resp.ContentLength > 0 {
		detail := formatProgress(downloaded, resp.ContentLength)
		notify.PhaseProgress(0, 1.0, detail)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// copyWithProgress reads from src into dst and hasher, reporting throttled progress.
func copyWithProgress(dst *os.File, src io.Reader, hasher hash.Hash, size int64, notify tui.PhaseNotifier) (int64, error) {
	downloaded := int64(0)
	lastProgress := time.Time{}
	buf := make([]byte, 32*1024)

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return downloaded, fmt.Errorf("failed to write: %w", werr)
			}
			_, _ = hasher.Write(buf[:n])
			downloaded += int64(n)

			if size > 0 && time.Since(lastProgress) >= 250*time.Millisecond {
				pct := float64(downloaded) / float64(size)
				notify.PhaseProgress(0, pct, formatProgress(downloaded, size))
				lastProgress = time.Now()
			}
		}
		if readErr == io.EOF {
			return downloaded, nil
		}
		if readErr != nil {
			return downloaded, fmt.Errorf("failed to download: %w", readErr)
		}
	}
}

// formatProgress returns a human-readable download progress string.
func formatProgress(downloaded, total int64) string {
	return fmt.Sprintf("%.1f / %.1f MB",
		float64(downloaded)/(1024*1024),
		float64(total)/(1024*1024))
}

// verifyChecksum checks the computed hash against the image's expected hash.
func verifyChecksum(w io.Writer, img *images.ImageInfo, computedHash string) error {
	if img.Hash == "" {
		fmt.Fprintln(w, "Warning: No checksum available for verification")
		return nil
	}

	fmt.Fprintf(w, "Verifying %s checksum...\n", img.HashAlgo)
	if computedHash != img.Hash {
		return &cmdutil.ErrHint{
			Err:  errors.New("checksum mismatch"),
			Hint: fmt.Sprintf("expected: %s\ncomputed: %s", img.Hash, computedHash),
		}
	}

	displayHash := computedHash
	if len(displayHash) > 16 {
		displayHash = displayHash[:16] + "..."
	}
	fmt.Fprintf(w, "Checksum verified: %s\n", displayHash)
	return nil
}

// convertImage converts the downloaded image to qcow2 format.
func convertImage(w io.Writer, src, dst string) error {
	fmt.Fprintln(w, "Converting to qcow2 format...")
	convertCmd := exec.Command("qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", src, dst)
	if output, err := convertCmd.CombinedOutput(); err != nil {
		// Try just renaming if conversion fails (might already be qcow2)
		if renameErr := os.Rename(src, dst); renameErr != nil {
			return fmt.Errorf("failed to convert image: %s: %w", string(output), err)
		}
	}
	return nil
}
