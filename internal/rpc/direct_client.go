package rpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"google.golang.org/grpc"
)

var errNotSupported = errors.New("operation not supported on this platform")

// DirectClient implements PrivilegeClient by executing operations directly
// as the current user, without privilege escalation. This is used on macOS
// where storage directories are user-owned and don't require root access.
type DirectClient struct{}

// NewDirectClient returns a new DirectClient.
func NewDirectClient() PrivilegeClient {
	return &DirectClient{}
}

func (c *DirectClient) Ping(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*StringMsg, error) {
	return &StringMsg{Message: "direct-client"}, nil
}

func (c *DirectClient) Shutdown(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*Empty, error) {
	return &Empty{}, nil
}

func (c *DirectClient) QemuImgCreate(ctx context.Context, in *QemuImgReq, opts ...grpc.CallOption) (*Empty, error) {
	args := []string{"create", "-f", "qcow2"}
	if in.BackingFile != "" {
		args = append(args, "-b", in.BackingFile, "-F", "qcow2")
	}
	args = append(args, in.Output)
	if in.Size != "" {
		args = append(args, in.Size)
	}

	cmd := exec.CommandContext(ctx, "qemu-img", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("qemu-img create failed: %s: %w", string(output), err)
	}
	return &Empty{}, nil
}

func (c *DirectClient) Chmod(ctx context.Context, in *ChmodReq, opts ...grpc.CallOption) (*Empty, error) {
	mode, err := strconv.ParseUint(in.Mode, 8, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid mode %q: %w", in.Mode, err)
	}
	if err := os.Chmod(in.Path, os.FileMode(mode)); err != nil {
		return nil, fmt.Errorf("chmod failed: %w", err)
	}
	return &Empty{}, nil
}

func (c *DirectClient) MkdirAll(ctx context.Context, in *MkdirReq, opts ...grpc.CallOption) (*Empty, error) {
	mode, err := strconv.ParseUint(in.Mode, 8, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid mode %q: %w", in.Mode, err)
	}
	if err := os.MkdirAll(in.Path, os.FileMode(mode)); err != nil {
		return nil, fmt.Errorf("mkdir failed: %w", err)
	}
	return &Empty{}, nil
}

func (c *DirectClient) RemoveAll(ctx context.Context, in *PathReq, opts ...grpc.CallOption) (*Empty, error) {
	if err := os.RemoveAll(in.Path); err != nil {
		return nil, fmt.Errorf("remove failed: %w", err)
	}
	return &Empty{}, nil
}

func (c *DirectClient) CopyFile(ctx context.Context, in *CopyReq, opts ...grpc.CallOption) (*Empty, error) {
	src, err := os.Open(in.Src)
	if err != nil {
		return nil, fmt.Errorf("failed to open source: %w", err)
	}
	defer src.Close()

	if err := os.MkdirAll(filepath.Dir(in.Dst), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create destination directory: %w", err)
	}

	dst, err := os.Create(in.Dst)
	if err != nil {
		return nil, fmt.Errorf("failed to create destination: %w", err)
	}

	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return nil, fmt.Errorf("copy failed: %w", err)
	}
	return &Empty{}, dst.Close()
}

// Linux-only operations return "not supported" errors.

func (c *DirectClient) UfwAdd(ctx context.Context, in *UfwReq, opts ...grpc.CallOption) (*Empty, error) {
	return nil, errNotSupported
}

func (c *DirectClient) UfwRemove(ctx context.Context, in *UfwReq, opts ...grpc.CallOption) (*Empty, error) {
	return nil, errNotSupported
}

func (c *DirectClient) UfwStatus(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*UfwStatusResp, error) {
	return nil, errNotSupported
}

func (c *DirectClient) IptablesAdd(ctx context.Context, in *IptablesReq, opts ...grpc.CallOption) (*Empty, error) {
	return nil, errNotSupported
}

func (c *DirectClient) IptablesRemove(ctx context.Context, in *IptablesReq, opts ...grpc.CallOption) (*Empty, error) {
	return nil, errNotSupported
}

func (c *DirectClient) IptablesFlush(ctx context.Context, in *IptablesFlushReq, opts ...grpc.CallOption) (*Empty, error) {
	return nil, errNotSupported
}
