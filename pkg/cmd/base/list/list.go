package list

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/images"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// imageJSON is the JSON representation of a base image.
type imageJSON struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Provider    string `json:"provider,omitempty"`
	Downloaded  bool   `json:"downloaded"`
	Size        int64  `json:"size_bytes,omitempty"`
	Custom      bool   `json:"custom,omitempty"`
}

// Options holds the options for the base list command.
type Options struct {
	Factory  *factory.Factory
	Exporter *cmdutil.Exporter
	Refresh  bool
}

// NewCmdList creates a new base list command.
func NewCmdList(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available and downloaded base images",
		Long: `List available and downloaded base images.

Shows both remotely available images and locally downloaded ones. Downloaded
images are marked with their file size. Use --refresh to update the list of
available images from cloud providers.`,
		Example: `  abox base list                           # Show available and downloaded images
  abox base ls                             # Short alias
  abox base list --json                    # JSON output
  abox base list --jq '.[].name'           # List image names only`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runF != nil {
				return runF(opts)
			}
			return runList(cmd.Context(), f, opts.Exporter, opts.Refresh)
		},
	}

	cmd.Flags().BoolVar(&opts.Refresh, "refresh", false, "Force refresh of available images from cloud providers")
	opts.Exporter = cmdutil.AddJSONFlags(cmd)

	return cmd
}

func runList(ctx context.Context, f *factory.Factory, exporter *cmdutil.Exporter, refresh bool) error {
	paths, err := config.GetPaths("")
	if err != nil {
		return err
	}

	// Fetch available images dynamically
	if refresh {
		fmt.Fprintln(f.IO.Out, "Refreshing available images...")
	}

	allImages, err := images.FetchAll(ctx, refresh)
	if err != nil {
		if exporter.Enabled() {
			return exporter.Write(f.IO.Out, []imageJSON{})
		}
		fmt.Fprintf(f.IO.Out, "Warning: failed to fetch available images: %v\n", err)
		fmt.Fprintln(f.IO.Out, "Showing only downloaded images.")
		return listDownloadedOnly(f, paths)
	}

	if exporter.Enabled() {
		return exportImagesJSON(f.IO.Out, exporter, allImages, paths)
	}

	f.IO.StartPager()
	defer f.IO.StopPager()

	out := f.IO.Out

	fmt.Fprintln(out, "Available base images:")
	fmt.Fprintln(out)

	knownImages := displayImagesByProvider(out, allImages, paths)
	displayCustomImages(out, knownImages, paths)

	return nil
}

func exportImagesJSON(out io.Writer, exporter *cmdutil.Exporter, allImages []images.ImageInfo, paths *config.Paths) error {
	knownImages := make(map[string]bool)
	var items []imageJSON

	for _, img := range allImages {
		knownImages[img.Name] = true
		item := imageJSON{
			Name:        img.Name,
			Description: img.Description,
			Provider:    img.Provider,
		}
		imagePath := filepath.Join(paths.UserBaseImages, img.Name+".qcow2")
		if info, err := os.Stat(imagePath); err == nil {
			item.Downloaded = true
			item.Size = info.Size()
		}
		items = append(items, item)
	}

	// Add custom images
	if entries, err := os.ReadDir(paths.UserBaseImages); err == nil {
		for _, entry := range entries {
			name := strings.TrimSuffix(entry.Name(), ".qcow2")
			if !knownImages[name] && strings.HasSuffix(entry.Name(), ".qcow2") {
				info, err := entry.Info()
				if err != nil {
					continue
				}
				items = append(items, imageJSON{
					Name:       name,
					Downloaded: true,
					Size:       info.Size(),
					Custom:     true,
				})
			}
		}
	}

	return exporter.Write(out, items)
}

func displayImagesByProvider(out io.Writer, allImages []images.ImageInfo, paths *config.Paths) map[string]bool {
	grouped := images.GroupByProvider(allImages)
	knownImages := make(map[string]bool)

	for _, provider := range images.ProviderOrder() {
		providerImages := grouped[provider]
		if len(providerImages) == 0 {
			continue
		}

		fmt.Fprintf(out, "%s:\n", images.ProviderDisplayName(provider))
		for _, img := range providerImages {
			knownImages[img.Name] = true
			imagePath := filepath.Join(paths.UserBaseImages, img.Name+".qcow2")
			status := ""
			if info, err := os.Stat(imagePath); err == nil {
				status = fmt.Sprintf("[downloaded, %s]", images.FormatSize(info.Size()))
			}
			fmt.Fprintf(out, "  %-15s %-35s %s\n", img.Name, img.Description, status)
		}
		fmt.Fprintln(out)
	}

	return knownImages
}

func displayCustomImages(out io.Writer, knownImages map[string]bool, paths *config.Paths) {
	entries, err := os.ReadDir(paths.UserBaseImages)
	if err != nil {
		return
	}

	var customImages []os.DirEntry
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".qcow2")
		if !knownImages[name] && strings.HasSuffix(entry.Name(), ".qcow2") {
			customImages = append(customImages, entry)
		}
	}

	if len(customImages) > 0 {
		fmt.Fprintln(out, "Custom images:")
		for _, entry := range customImages {
			name := strings.TrimSuffix(entry.Name(), ".qcow2")
			info, err := entry.Info()
			if err != nil {
				continue
			}
			fmt.Fprintf(out, "  %-15s %s\n", name, images.FormatSize(info.Size()))
		}
	}
}

// listDownloadedOnly lists only downloaded images when cloud fetch fails.
func listDownloadedOnly(f *factory.Factory, paths *config.Paths) error {
	out := f.IO.Out
	entries, err := os.ReadDir(paths.UserBaseImages)
	if os.IsNotExist(err) {
		fmt.Fprintln(out, "No base images downloaded.")
		fmt.Fprintln(out, "Use 'abox base pull' to download an image.")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read base images directory: %w", err)
	}

	fmt.Fprintln(out, "Downloaded images:")
	hasImages := false
	for _, entry := range entries {
		if before, ok := strings.CutSuffix(entry.Name(), ".qcow2"); ok {
			name := before
			info, err := entry.Info()
			if err != nil {
				continue
			}
			fmt.Fprintf(out, "  %-15s %s\n", name, images.FormatSize(info.Size()))
			hasImages = true
		}
	}

	if !hasImages {
		fmt.Fprintln(out, "  (none)")
		fmt.Fprintln(out, "\nUse 'abox base pull' to download an image.")
	}

	return nil
}
