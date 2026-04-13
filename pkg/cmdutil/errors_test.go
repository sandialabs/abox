package cmdutil_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestErrCancel(t *testing.T) {
	var err error = &cmdutil.ErrCancel{}
	if err.Error() != "cancelled" {
		t.Fatalf("unexpected message: %s", err.Error())
	}
	var target *cmdutil.ErrCancel
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match ErrCancel")
	}
}

func TestErrSilent(t *testing.T) {
	var err error = &cmdutil.ErrSilent{}
	if err.Error() != "silent error" {
		t.Fatalf("unexpected message: %s", err.Error())
	}
	var target *cmdutil.ErrSilent
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match ErrSilent")
	}
}

func TestErrFlag(t *testing.T) {
	inner := fmt.Errorf("bad flag value")
	var err error = &cmdutil.ErrFlag{Err: inner}
	if err.Error() != "bad flag value" {
		t.Fatalf("unexpected message: %s", err.Error())
	}
	var target *cmdutil.ErrFlag
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match ErrFlag")
	}
	if !errors.Is(err, inner) {
		t.Fatal("errors.Is should match inner error")
	}
}

func TestFlagErrorf(t *testing.T) {
	err := cmdutil.FlagErrorf("invalid value %q for --%s", "abc", "count")
	if err.Error() != `invalid value "abc" for --count` {
		t.Fatalf("unexpected message: %s", err.Error())
	}
	var target *cmdutil.ErrFlag
	if !errors.As(err, &target) {
		t.Fatal("FlagErrorf should return *ErrFlag")
	}
}

func TestMutuallyExclusive_None(t *testing.T) {
	err := cmdutil.MutuallyExclusive(
		[]string{"--json", "--template"},
		[]bool{false, false},
	)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestMutuallyExclusive_One(t *testing.T) {
	err := cmdutil.MutuallyExclusive(
		[]string{"--json", "--template"},
		[]bool{true, false},
	)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestMutuallyExclusive_Two(t *testing.T) {
	err := cmdutil.MutuallyExclusive(
		[]string{"--json", "--template"},
		[]bool{true, true},
	)
	if err == nil {
		t.Fatal("expected error for two flags set")
	}
	var target *cmdutil.ErrFlag
	if !errors.As(err, &target) {
		t.Fatal("MutuallyExclusive should return *ErrFlag")
	}
	if err.Error() != "specify only one of --json or --template" {
		t.Fatalf("unexpected message: %s", err.Error())
	}
}

func TestMutuallyExclusive_Three(t *testing.T) {
	err := cmdutil.MutuallyExclusive(
		[]string{"--json", "--template", "--web"},
		[]bool{true, true, true},
	)
	if err == nil {
		t.Fatal("expected error for three flags set")
	}
	if err.Error() != "specify only one of --json, --template, or --web" {
		t.Fatalf("unexpected message: %s", err.Error())
	}
}

func TestErrHint(t *testing.T) {
	inner := fmt.Errorf("instance %q already exists", "test")
	var err error = &cmdutil.ErrHint{Err: inner, Hint: "Use a different name"}
	if err.Error() != `instance "test" already exists` {
		t.Fatalf("unexpected message: %s", err.Error())
	}
	var target *cmdutil.ErrHint
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match ErrHint")
	}
	if target.Hint != "Use a different name" {
		t.Fatalf("unexpected hint: %s", target.Hint)
	}
	if !errors.Is(err, inner) {
		t.Fatal("errors.Is should match inner error")
	}
}

func TestErrHint_Wrapped(t *testing.T) {
	inner := fmt.Errorf("read failed: %w", fmt.Errorf("permission denied"))
	var err error = &cmdutil.ErrHint{Err: inner, Hint: "Check file permissions"}
	var target *cmdutil.ErrHint
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match ErrHint through wrapping")
	}
}

func TestNoResultsError(t *testing.T) {
	var err error = &cmdutil.NoResultsError{Message: "no instances found"}
	if err.Error() != "no instances found" {
		t.Fatalf("unexpected message: %s", err.Error())
	}
	var target *cmdutil.NoResultsError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match NoResultsError")
	}
}
