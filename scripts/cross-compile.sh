#!/usr/bin/env bash
# Cross-compile gate for cross-platform enablement (see docs/dev plan).
#
# The whole tree now cross-compiles: every Linux-only primitive lives behind an
# OS seam (internal/sysutil, internal/procutil, OS-gated files in
# internal/privilege / internal/images, etc.). So the build step builds the
# ENTIRE tree for each non-Linux target rather than a hand-picked list:
#   GOOS=$os go build ./...   proves all non-test code type-checks on the target.
#
# The vet step is DELIBERATELY SCOPED to VET_PKGS rather than ./..., and this is
# the honest limitation of the gate: `go vet` also type-checks _test.go files,
# and some Linux-only test files legitimately import Linux-only packages (e.g.
# pkg/cmd/overrides/dump/dump_test.go blank-imports internal/backend/libvirt to
# register its defaults). Those test files are excluded from a non-Linux build by
# their own constraints at test time, but `go vet ./...` still tries to load them
# and fails. So we vet only the genuinely cross-platform packages — which is
# exactly where the OS-gated fail-closed TEST stubs live (the *_other_test.go
# assertions in sysutil/procutil/privilege/rpc). Vetting them here compiles those
# stubs for the target; the ci.yaml non-linux-test job actually EXECUTES them on
# real macOS/Windows runners. VET_PKGS mirrors that job's package list — keep the
# two consistent.
#
# This is the authoritative portability check. scripts/check-portable-imports.sh
# is only a fast pre-filter for a specific class of regression.
set -euo pipefail

# The deliberately-chosen set of cross-platform packages that CARRY OS-GATED
# TESTS — NOT the full set of darwin/windows-buildable packages. Each entry has
# been confirmed to build on both darwin and windows (via GOOS=... go build/vet);
# darwin-only packages (e.g. internal/vfkit) simply have no test files on windows,
# which vet/test treat as non-fatal. Mirrors ci.yaml's non-linux-test job — add a
# package to both places when it gains gated tests.
VET_PKGS=(
  ./internal/sysutil/...
  ./internal/procutil/...
  ./internal/privilege/...
  ./internal/rpc/...
  ./internal/config/...
  ./internal/fsutil/...
  ./internal/logging/...
  ./internal/vmrun/...
  ./internal/vfkit/...
  ./internal/vmnethelper/...
  ./internal/backend/vfkit/...
  ./internal/backend/egress/...
  ./internal/backend/vmware/...
  ./internal/backend/conformance/...
  ./internal/dnsfilter/...
  ./internal/daemon/...
  ./pkg/cmd/checkdeps/...
  ./pkg/cmd/start/...
)

status=0
for os in darwin windows; do
  echo "==> GOOS=$os go build ./..."
  if GOOS="$os" go build ./...; then
    echo "    ok"
  else
    echo "    FAILED for GOOS=$os" >&2
    status=1
  fi

  # go vet type-checks test files too (go build does not), so this compile-checks
  # the OS-gated fail-closed test stubs on each target. Scoped to VET_PKGS — see
  # the header for why ./... cannot be vetted off Linux.
  echo "==> GOOS=$os go vet (cross-platform test-stub packages)"
  if GOOS="$os" go vet "${VET_PKGS[@]}"; then
    echo "    ok"
  else
    echo "    FAILED for GOOS=$os" >&2
    status=1
  fi
done

# internal/vmrun's fail-loud fallback (netcfg_other.go / hosttype_other.go) is
# tagged for platforms that are neither linux, darwin, nor windows — so the
# darwin/windows gate above never compiles it. Vet the package for one such OS
# (freebsd) so a typo in the fallback OR its test (netcfg_other_test.go) is caught
# in CI. `go vet` (not `go build`) is used so the test file is compiled too; the
# package is fully portable, so vetting ./internal/vmrun/... off-Linux is safe.
echo "==> GOOS=freebsd go vet ./internal/vmrun/... (exercises the _other.go fallback + its test)"
if GOOS=freebsd go vet ./internal/vmrun/...; then
  echo "    ok"
else
  echo "    FAILED for GOOS=freebsd" >&2
  status=1
fi

exit "$status"
