//go:build linux

package privilege

import (
	"crypto/sha256"
	"fmt"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/validation"
)

// This file is the helper-side authorization of egress requests: host iptables
// is global, so without it any user's root helper would rewrite any other
// user's chains — ValidateBridgeName alone only checks syntax. The model
// mirrors EnsureStorageRoot's "allowlist of one": the owned resource is
// recomputed from the socket-peer uid (never from request contents) and the
// request must name exactly that resource.
//
// The derivations below MUST match config.GenerateBridgeName and
// config.LegacyBridgeName; they are hardcoded here (not imported) so the
// trusted code states explicitly what it authorizes, following the
// libvirtImagesParent convention (storage_linux.go). A sync test in this
// package (tests are not TCB) asserts the two stay identical.

// ownedBridgeName recomputes the per-user bridge for (uid, instance):
// "abx-" + first 11 hex chars of sha256("<uid>/<instance>"). The "abx-" prefix
// is disjoint from both legacy derivations ("abox-", "ab-"), so a legacy name
// can never collide with — and thereby get legacy-leniency teardown on —
// another user's current per-user bridge.
func ownedBridgeName(uid int, instance string) string {
	h := sha256.Sum256(fmt.Appendf(nil, "%d/%s", uid, instance))
	return "abx-" + fmt.Sprintf("%x", h[:6])[:11]
}

// legacyBridgeName returns the pre-multi-user (name-only) bridge derivation
// for an instance: "abox-<name>" when it fits the 15-char interface limit, else
// "ab-" + first 12 hex chars of sha256(name).
func legacyBridgeName(instance string) string {
	if len("abox-"+instance) <= 15 {
		return "abox-" + instance
	}
	h := sha256.Sum256([]byte(instance))
	return fmt.Sprintf("ab-%x", h[:6])
}

// vmnet interface names ("vmnetN") are matched with safeVMNetName from
// validation.go — same package, so validation and authorization cannot drift.
// (The hardcoded-derivation rule above covers values copied from OTHER
// packages, not in-package definitions.)

// egressOp distinguishes rule-installing requests from teardown and read-only
// requests for authorization purposes (see authorizeBridge), and names the
// operation in audit records.
type egressOp int

const (
	egressApply  egressOp = iota // install/replace rules
	egressRemove                 // flush rules
	egressVerify                 // read rule state only
)

func (op egressOp) String() string {
	switch op {
	case egressApply:
		return "apply"
	case egressRemove:
		return "remove"
	case egressVerify:
		return "verify"
	}
	return "unknown"
}

// authorizeBridge decides whether the calling uid may run an egress operation on
// the request's bridge:
//
//  1. The bridge recomputed from (peer uid, request instance) — the caller's own
//     per-user bridge — is always authorized.
//  2. A bridge matching the LEGACY name-only derivation of the instance is
//     authorized for Remove/Verify only, audit-logged: ownership of a legacy name
//     is unverifiable (any user can derive it), but stop/remove of a pre-multi-user
//     instance — and the start-time name upgrade itself — must keep working.
//     Apply is refused: `abox start` upgrades the instance to per-user names
//     before it ever applies rules, so a legacy Apply only ever comes from an
//     outdated or hostile client. The residual (another user flushing a legacy
//     instance's chains until its next start) is no worse than the pre-check
//     state and ends with the upgrade.
//  3. vmnetN interfaces are authorized with an audit record: they are VMware
//     infrastructure, not derivable from (uid, instance); the vmware backend is
//     an explicit experimental opt-in (ABOX_BACKEND=vmware).
//  4. Everything else — including an empty instance name, which an up-to-date
//     abox always sends — is refused. The caller binary is not trusted:
//     leniency for a missing field would be a bypass.
func authorizeBridge(allowedUID int, req *rpc.EgressReq, op egressOp) error {
	if req.Instance == "" {
		return fmt.Errorf("egress request for bridge %q carries no instance name; "+
			"abox and abox-helper versions must match", req.Bridge)
	}
	if err := validation.ValidateInstanceName(req.Instance); err != nil {
		return fmt.Errorf("invalid instance name in egress request: %w", err)
	}

	if req.Bridge == ownedBridgeName(allowedUID, req.Instance) {
		return nil
	}

	if req.Bridge == legacyBridgeName(req.Instance) {
		if op == egressApply {
			return fmt.Errorf("bridge %q uses the legacy shared-name scheme, whose ownership "+
				"cannot be verified; stop the instance and start it with an up-to-date abox to "+
				"upgrade it to per-user names", req.Bridge)
		}
		logging.Audit("privilege-helper.egress", "warning", fmt.Sprintf("%s on legacy-named bridge (ownership unverifiable)", op),
			"bridge", req.Bridge, "instance", req.Instance, "caller_uid", allowedUID)
		return nil
	}

	if safeVMNetName.MatchString(req.Bridge) {
		logging.Audit("privilege-helper.egress", "warning", fmt.Sprintf("%s on shared vmnet interface (ownership not derivable)", op),
			"bridge", req.Bridge, "instance", req.Instance, "caller_uid", allowedUID)
		return nil
	}

	return fmt.Errorf("bridge %q is not derivable from instance %q for uid %d",
		req.Bridge, req.Instance, allowedUID)
}
