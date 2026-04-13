package scp

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/sshutil"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the scp command.
type Options struct {
	Factory   *factory.Factory
	Recursive bool
	Preserve  bool
	Srcs      []string // Source paths (positional args)
	Dst       string   // Destination path (last positional arg)
}

// NewCmdSCP creates a new scp command.
func NewCmdSCP(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "scp [flags] <source>... <destination>",
		Short: "Copy files to/from an abox instance",
		Long: `Copy files to or from a running instance using scp.

Use <instance>:<path> syntax to specify remote paths.
Multiple source files can be specified in a single command.`,
		Example: `  abox scp ./myfile.txt dev:/home/ubuntu/       # host → VM
  abox scp dev:/home/ubuntu/file.txt ./         # VM → host
  abox scp -r ./mydir dev:/home/ubuntu/         # recursive copy
  abox scp -p dev:/tmp/data.txt ./              # preserve times
  abox scp a.txt b.txt dev:/home/ubuntu/        # multiple files
  abox scp dev:/tmp/a.txt dev:/tmp/b.txt ./     # multiple remote files`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Srcs = args[:len(args)-1]
			opts.Dst = args[len(args)-1]
			if runF != nil {
				return runF(opts)
			}
			return opts.Run()
		},
	}

	cmd.Flags().BoolVarP(&opts.Recursive, "recursive", "r", false, "Copy directories recursively")
	cmd.Flags().BoolVarP(&opts.Preserve, "preserve", "p", false, "Preserve modification times")

	return cmd
}

// parseRemotePath parses a path that may be in <instance>:<path> format.
// Returns (instance, path, isRemote).
func parseRemotePath(path string) (string, string, bool) {
	// Check for instance:path format
	// Be careful not to match Windows drive letters or absolute paths
	if idx := strings.Index(path, ":"); idx > 0 {
		// Make sure it's not a Windows drive letter (single char before colon)
		if idx > 1 || (idx == 1 && path[0] != '/') {
			instName := path[:idx]
			remotePath := path[idx+1:]
			return instName, remotePath, true
		}
	}
	return "", path, false
}

// parsedSource holds a parsed source path with its instance, path, and remote flag.
type parsedSource struct {
	instance string
	path     string
	remote   bool
}

// parsedArgs holds the validated and parsed arguments for an scp operation.
type parsedArgs struct {
	sources      []parsedSource
	dstPath      string
	instanceName string
	srcsRemote   bool
}

// parseAndValidateArgs parses and validates the source and destination arguments.
func parseAndValidateArgs(srcs []string, dst string) (*parsedArgs, error) {
	dstInstance, dstPath, dstRemote := parseRemotePath(dst)

	sources := make([]parsedSource, len(srcs))
	for i, s := range srcs {
		inst, path, remote := parseRemotePath(s)
		sources[i] = parsedSource{inst, path, remote}
	}

	srcsRemote := sources[0].remote
	for _, s := range sources[1:] {
		if s.remote != srcsRemote {
			return nil, errors.New("all source paths must be the same type (all local or all remote)")
		}
	}

	// Validate: exactly one side must be remote
	if srcsRemote && dstRemote {
		return nil, errors.New("cannot copy between two remote instances; one side must be local")
	}
	if !srcsRemote && !dstRemote {
		return nil, errors.New("at least one path must be remote (use <instance>:<path> format)")
	}

	// If sources are remote, they must all be from the same instance
	var instanceName string
	if srcsRemote {
		instanceName = sources[0].instance
		for _, s := range sources[1:] {
			if s.instance != instanceName {
				return nil, fmt.Errorf("all remote sources must be from the same instance (got %q and %q)", instanceName, s.instance)
			}
		}
	} else {
		instanceName = dstInstance
	}

	return &parsedArgs{
		sources:      sources,
		dstPath:      dstPath,
		instanceName: instanceName,
		srcsRemote:   srcsRemote,
	}, nil
}

// buildSCPArgs constructs the scp command-line arguments including remote paths.
func (o *Options) buildSCPArgs(pa *parsedArgs, sshUser, ip string, paths *config.Paths) []string {
	scpArgs := sshutil.CommonOptions(paths)

	if o.Recursive {
		scpArgs = append(scpArgs, "-r")
	}
	if o.Preserve {
		scpArgs = append(scpArgs, "-p")
	}

	if pa.srcsRemote {
		for _, s := range pa.sources {
			scpArgs = append(scpArgs, sshutil.RemotePath(sshUser, ip, s.path))
		}
		scpArgs = append(scpArgs, pa.dstPath)
	} else {
		for _, s := range pa.sources {
			scpArgs = append(scpArgs, s.path)
		}
		scpArgs = append(scpArgs, sshutil.RemotePath(sshUser, ip, pa.dstPath))
	}

	return scpArgs
}

// Run executes the scp command.
func (o *Options) Run() error {
	pa, err := parseAndValidateArgs(o.Srcs, o.Dst)
	if err != nil {
		return err
	}

	factory.Ensure(&o.Factory)
	be, err := o.Factory.BackendFor(pa.instanceName)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	inst, paths, err := instance.LoadRunning(pa.instanceName, be.VM())
	if err != nil {
		return err
	}

	ip, err := instance.GetIP(inst, be.VM())
	if err != nil {
		return err
	}

	scpArgs := o.buildSCPArgs(pa, inst.GetUser(), ip, paths)

	// Find scp binary
	scpBin, err := exec.LookPath("scp")
	if err != nil {
		return fmt.Errorf("scp not found: %w", err)
	}

	// Determine direction for logging
	direction := "upload"
	if pa.srcsRemote {
		direction = "download"
	}

	// Log SCP access before exec replaces this process
	logging.AuditInstance(pa.instanceName, logging.ActionSCP, "direction", direction)

	// Replace current process with scp
	return syscall.Exec(scpBin, append([]string{"scp"}, scpArgs...), os.Environ())
}
