#!/usr/bin/env bash
# Import-guard for cross-platform enablement (see docs/dev plan).
#
# AUTHORITATIVE CHECK: scripts/cross-compile.sh builds and vets the WHOLE tree
# for GOOS=darwin and GOOS=windows. That is the real portability gate. THIS
# script is only a fast, tree-wide PRE-FILTER: it flags the cheap-to-detect
# regression (a platform-specific IMPORT in a non-gated file) without a full
# cross-compile, so it can fail early in local hooks / editors.
#
# It fails if a *portable* Go source file (one that is NOT gated to a specific OS
# via a build-tag or an OS/arch filename suffix) imports a platform-specific
# package: golang.org/x/sys/unix or log/syslog. These are the imports that
# silently break GOOS=windows builds (log/syslog in particular masked the whole
# tree). New platform-specific code must live in a build-tagged seam file
# (e.g. foo_unix.go / foo_other.go) like internal/fsutil/reflink_*.go.
#
# KNOWN BLIND SPOT: bare use of the `syscall` package (e.g. syscall.Kill,
# syscall.SysProcAttr) in a non-gated file is NOT caught here. `syscall` also
# exports plenty of portable symbols, so grepping for it would false-positive;
# distinguishing portable from non-portable use requires a real type-check.
# That is exactly what the cross-compile gate does, so bare-`syscall` breakage is
# caught there, not here. Do not try to add naive `syscall` detection to this
# pre-filter.
set -euo pipefail

# Imports that must only ever appear in OS-gated files. (Bare `syscall` is a
# deliberate omission — see KNOWN BLIND SPOT above; it is caught by
# cross-compile.sh.)
FORBIDDEN_RE='"(golang\.org/x/sys/unix|log/syslog)"'

# Known pre-existing Linux-only files awaiting their OS seam. The guard
# grandfathers these so it blocks only NEW regressions; remove each entry when
# that file is seamed. Now empty: every Linux-only file carries a //go:build tag.
EXCEPTIONS=()

is_exception() {
  local f="$1"
  for e in "${EXCEPTIONS[@]:-}"; do
    [[ -n "$e" && "$f" == "$e" ]] && return 0
  done
  return 1
}

# A file is considered OS-gated (and therefore exempt) if its name carries a
# GOOS/GOARCH suffix or it declares a //go:build constraint.
is_os_gated() {
  local f="$1"
  case "$(basename "$f")" in
    *_linux.go|*_darwin.go|*_windows.go|*_unix.go|*_other.go|\
    *_bsd.go|*_freebsd.go|*_openbsd.go|*_netbsd.go|*_dragonfly.go|\
    *_solaris.go|*_aix.go|*_plan9.go|*_js.go|*_wasm.go|*_android.go|*_ios.go)
      return 0 ;;
  esac
  # Any explicit build constraint counts as intentional gating; a wrong
  # constraint is caught by the cross-compile gate, not here.
  if grep -qE '^//go:build' "$f"; then
    return 0
  fi
  return 1
}

violations=0
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  is_os_gated "$f" && continue
  is_exception "$f" && continue
  if grep -qE "$FORBIDDEN_RE" "$f"; then
    echo "forbidden platform-specific import in non-gated file: $f" >&2
    grep -nE "$FORBIDDEN_RE" "$f" >&2 || true
    violations=$((violations + 1))
  fi
done < <({ git ls-files '*.go'; git ls-files --others --exclude-standard '*.go'; } | sort -u)

if [[ "$violations" -gt 0 ]]; then
  echo "" >&2
  echo "Found $violations file(s) with platform-specific imports outside an OS-gated seam." >&2
  echo "Move the code into a build-tagged file (e.g. *_unix.go + *_other.go)." >&2
  exit 1
fi

echo "import-guard: no platform-specific imports in non-gated files"
