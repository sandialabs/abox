package cmdutil_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func newPrompter(input string) *cmdutil.LivePrompter {
	io := &iostreams.IOStreams{
		In:     strings.NewReader(input),
		Out:    &bytes.Buffer{},
		ErrOut: &bytes.Buffer{},
	}
	return cmdutil.NewLivePrompter(io)
}

func TestConfirm_Yes(t *testing.T) {
	p := newPrompter("y\n")
	if !p.Confirm("Continue? ") {
		t.Fatal("expected true for 'y'")
	}
}

func TestConfirm_YesFull(t *testing.T) {
	p := newPrompter("yes\n")
	if !p.Confirm("Continue? ") {
		t.Fatal("expected true for 'yes'")
	}
}

func TestConfirm_No(t *testing.T) {
	p := newPrompter("n\n")
	if p.Confirm("Continue? ") {
		t.Fatal("expected false for 'n'")
	}
}

func TestConfirm_EmptyDefaultNo(t *testing.T) {
	p := newPrompter("\n")
	if p.Confirm("Continue? ") {
		t.Fatal("expected false for empty input with default no")
	}
}

func TestConfirmWithDefault_EmptyDefaultYes(t *testing.T) {
	p := newPrompter("\n")
	if !p.ConfirmWithDefault("Continue? ", true) {
		t.Fatal("expected true for empty input with default yes")
	}
}

func TestConfirm_EOF(t *testing.T) {
	p := newPrompter("")
	if p.Confirm("Continue? ") {
		t.Fatal("expected false on EOF")
	}
}

func TestSelect_ValidChoice(t *testing.T) {
	opts := []cmdutil.Option{
		{Label: "alpha"},
		{Label: "beta"},
		{Label: "gamma"},
	}
	p := newPrompter("2\n")
	got := p.Select("Pick one:", opts)
	if got != 1 {
		t.Fatalf("expected index 1, got %d", got)
	}
}

func TestSelect_OutOfRange(t *testing.T) {
	opts := []cmdutil.Option{
		{Label: "alpha"},
		{Label: "beta"},
	}
	p := newPrompter("5\n")
	got := p.Select("Pick one:", opts)
	if got != -1 {
		t.Fatalf("expected -1 for out-of-range, got %d", got)
	}
}

func TestSelect_EmptyInput(t *testing.T) {
	opts := []cmdutil.Option{
		{Label: "alpha"},
	}
	p := newPrompter("\n")
	got := p.Select("Pick one:", opts)
	if got != -1 {
		t.Fatalf("expected -1 for empty input, got %d", got)
	}
}

func TestSelect_NoOptions(t *testing.T) {
	p := newPrompter("1\n")
	got := p.Select("Pick one:", nil)
	if got != -1 {
		t.Fatalf("expected -1 for no options, got %d", got)
	}
}

func TestSelectWithGroups_ValidChoice(t *testing.T) {
	groups := map[string][]cmdutil.Option{
		"Fruits":     {{Label: "apple"}, {Label: "banana"}},
		"Vegetables": {{Label: "carrot"}},
	}
	order := []string{"Fruits", "Vegetables"}

	// Select "carrot" which is item 3 (index 2)
	p := newPrompter("3\n")
	got := p.SelectWithGroups("Pick:", groups, order)
	if got != 2 {
		t.Fatalf("expected index 2, got %d", got)
	}
}

func TestSelectWithGroups_FirstItem(t *testing.T) {
	groups := map[string][]cmdutil.Option{
		"A": {{Label: "one"}},
		"B": {{Label: "two"}},
	}
	order := []string{"A", "B"}

	p := newPrompter("1\n")
	got := p.SelectWithGroups("Pick:", groups, order)
	if got != 0 {
		t.Fatalf("expected index 0, got %d", got)
	}
}

func TestSelectWithGroups_OutOfRange(t *testing.T) {
	groups := map[string][]cmdutil.Option{
		"A": {{Label: "one"}},
	}
	order := []string{"A"}

	p := newPrompter("99\n")
	got := p.SelectWithGroups("Pick:", groups, order)
	if got != -1 {
		t.Fatalf("expected -1 for out-of-range, got %d", got)
	}
}

func TestSelectWithGroups_EmptyGroups(t *testing.T) {
	p := newPrompter("1\n")
	got := p.SelectWithGroups("Pick:", nil, nil)
	if got != -1 {
		t.Fatalf("expected -1 for empty groups, got %d", got)
	}
}

func TestInput_WithValue(t *testing.T) {
	p := newPrompter("MyValue\n")
	got := p.Input("Name", "")
	if got != "MyValue" {
		t.Fatalf("expected %q, got %q", "MyValue", got)
	}
}

func TestInput_EmptyUsesDefault(t *testing.T) {
	p := newPrompter("\n")
	got := p.Input("Name", "default-val")
	if got != "default-val" {
		t.Fatalf("expected %q, got %q", "default-val", got)
	}
}

func TestInput_PreservesCase(t *testing.T) {
	p := newPrompter("CamelCase\n")
	got := p.Input("Name", "")
	if got != "CamelCase" {
		t.Fatalf("expected %q, got %q", "CamelCase", got)
	}
}

func TestMultiSelect_ValidChoices(t *testing.T) {
	opts := []cmdutil.Option{
		{Label: "alpha"},
		{Label: "beta"},
		{Label: "gamma"},
	}
	p := newPrompter("1 3\n")
	got := p.MultiSelect("Pick:", opts)
	if len(got) != 2 || got[0] != 0 || got[1] != 2 {
		t.Fatalf("expected [0 2], got %v", got)
	}
}

func TestMultiSelect_EmptySkips(t *testing.T) {
	opts := []cmdutil.Option{
		{Label: "alpha"},
	}
	p := newPrompter("\n")
	got := p.MultiSelect("Pick:", opts)
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestMultiSelect_InvalidReturnsNil(t *testing.T) {
	opts := []cmdutil.Option{
		{Label: "alpha"},
		{Label: "beta"},
	}
	p := newPrompter("1 5\n")
	got := p.MultiSelect("Pick:", opts)
	if got != nil {
		t.Fatalf("expected nil for invalid input, got %v", got)
	}
}

func TestMultiSelect_DeduplicatesInput(t *testing.T) {
	opts := []cmdutil.Option{
		{Label: "alpha"},
		{Label: "beta"},
	}
	p := newPrompter("1 1 2\n")
	got := p.MultiSelect("Pick:", opts)
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("expected [0 1], got %v", got)
	}
}

func TestMultiSelect_NoOptions(t *testing.T) {
	p := newPrompter("1\n")
	got := p.MultiSelect("Pick:", nil)
	if got != nil {
		t.Fatalf("expected nil for no options, got %v", got)
	}
}
