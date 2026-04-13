package allowlist

import (
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/validation"
)

// ModeServer interface that both DNS and HTTP servers implement.
type ModeServer interface {
	SetActive(bool)
	IsActive() bool
	GetMode() string
	GetProfileLogger() *ProfileLogger
}

// AllowlistAPIHandler provides shared allowlist API methods.
// Embed this in API servers to avoid code duplication.
type AllowlistAPIHandler struct {
	Filter *Filter
	Loader *Loader
	Server ModeServer
}

// Add adds a domain to the allowlist.
func (h *AllowlistAPIHandler) Add(domain string) (*rpc.StringMsg, error) {
	domain = NormalizeDomain(domain)

	// Validate domain format
	if err := validation.ValidateDomain(strings.TrimSuffix(domain, ".")); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid domain: %v", err)
	}

	if h.Filter.Add(domain) {
		if h.Loader != nil {
			if err := h.Loader.SaveDomain(strings.TrimSuffix(domain, ".")); err != nil {
				// Domain is added to in-memory filter but failed to persist.
				// Return as error so RPC callers can handle it.
				return nil, status.Errorf(codes.Internal, "added %s to filter but failed to save to allowlist file: %v", domain, err)
			}
		}
		return &rpc.StringMsg{Message: "added " + domain}, nil
	}

	return &rpc.StringMsg{Message: domain + " is already in the allowlist"}, nil
}

// Remove removes a domain from the allowlist.
func (h *AllowlistAPIHandler) Remove(domain string) (*rpc.StringMsg, error) {
	domain = NormalizeDomain(domain)

	// Validate domain format
	if err := validation.ValidateDomain(strings.TrimSuffix(domain, ".")); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid domain: %v", err)
	}

	if h.Filter.Remove(domain) {
		return &rpc.StringMsg{Message: fmt.Sprintf("removed %s (edit the allowlist file to persist)", domain)}, nil
	}

	return nil, status.Errorf(codes.NotFound, "%s not found in allowlist", domain)
}

// List returns all domains in the allowlist.
func (h *AllowlistAPIHandler) List() (*rpc.DomainList, error) {
	domains := h.Filter.List()
	return &rpc.DomainList{Domains: domains}, nil
}

// Reload reloads the allowlist from file.
func (h *AllowlistAPIHandler) Reload() (*rpc.StringMsg, error) {
	if h.Loader == nil {
		return nil, status.Error(codes.FailedPrecondition, "no allowlist file loaded")
	}

	if err := h.Loader.Load(); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to reload: %v", err)
	}

	return &rpc.StringMsg{Message: fmt.Sprintf("reloaded %d domains from file", h.Filter.Count())}, nil
}

// SetMode sets the filtering mode (active or passive).
// If mode is empty, returns the current mode.
func (h *AllowlistAPIHandler) SetMode(mode string) (*rpc.StringMsg, error) {
	if mode == "" {
		// Return current mode
		return &rpc.StringMsg{Message: "mode: " + h.Server.GetMode()}, nil
	}

	mode = strings.ToLower(mode)
	switch mode {
	case ModeActive:
		h.Server.SetActive(true)
		return &rpc.StringMsg{Message: "mode: " + ModeActive}, nil
	case ModePassive:
		h.Server.SetActive(false)
		return &rpc.StringMsg{Message: "mode: " + ModePassive}, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "invalid mode: %s (must be %s or %s)", mode, ModeActive, ModePassive)
	}
}

// Profile manages the profile log.
func (h *AllowlistAPIHandler) Profile(subcmd string) (*rpc.ProfileResp, error) {
	subcmd = strings.ToLower(subcmd)
	logger := h.Server.GetProfileLogger()

	switch subcmd {
	case "show", "list":
		if logger == nil {
			return &rpc.ProfileResp{
				Message: "no domains captured (profile logger not initialized)",
				Domains: []string{},
			}, nil
		}
		domains := logger.GetDomains()
		return &rpc.ProfileResp{Domains: domains}, nil

	case "export":
		if logger == nil {
			return &rpc.ProfileResp{Message: "# No domains captured\n"}, nil
		}
		return &rpc.ProfileResp{Message: logger.ExportAsAllowlist()}, nil

	case "clear":
		if logger == nil {
			return &rpc.ProfileResp{Message: "no domains to clear"}, nil
		}
		if err := logger.Clear(); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to clear: %v", err)
		}
		return &rpc.ProfileResp{Message: "profile log cleared"}, nil

	case "count":
		if logger == nil {
			return &rpc.ProfileResp{Count: 0}, nil
		}
		return &rpc.ProfileResp{Count: int32(logger.Count())}, nil //nolint:gosec // count is bounded by allowlist size

	default:
		return nil, status.Errorf(codes.InvalidArgument, "invalid subcommand: %s (must be show, export, clear, or count)", subcmd)
	}
}
