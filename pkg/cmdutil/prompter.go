package cmdutil

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/sandialabs/abox/internal/iostreams"
)

// Option represents a selectable option in a menu.
type Option struct {
	Label       string // Display text for the option
	Description string // Additional description (optional)
}

// Prompter provides interactive prompt methods.
type Prompter interface {
	Confirm(message string) bool
	ConfirmWithDefault(message string, defaultYes bool) bool
	Select(prompt string, options []Option) int
	SelectWithGroups(prompt string, groups map[string][]Option, groupOrder []string) int
	Input(prompt string, defaultValue string) string
	MultiSelect(prompt string, options []Option) []int
}

// LivePrompter implements Prompter using the IOStreams' In and Out.
type LivePrompter struct {
	reader *bufio.Reader
	out    io.Writer
}

// NewLivePrompter creates a Prompter that reads from io.In and writes to io.ErrOut.
// Prompts go to ErrOut so they don't pollute piped stdout.
func NewLivePrompter(io *iostreams.IOStreams) *LivePrompter {
	return &LivePrompter{reader: bufio.NewReader(io.In), out: io.ErrOut}
}

func (p *LivePrompter) readLine() string {
	// On error/EOF, treat as empty input (cancel).
	response, _ := p.reader.ReadString('\n')
	return strings.TrimSpace(strings.ToLower(response))
}

func (p *LivePrompter) readRawLine() string {
	response, _ := p.reader.ReadString('\n')
	return strings.TrimSpace(response)
}

func (p *LivePrompter) readSelection() int {
	response, _ := p.reader.ReadString('\n')
	response = strings.TrimSpace(response)
	if response == "" {
		return -1
	}
	var selection int
	if _, err := fmt.Sscanf(response, "%d", &selection); err != nil {
		return -1
	}
	return selection
}

// Confirm prompts the user with a yes/no question (default: no).
func (p *LivePrompter) Confirm(message string) bool {
	return p.ConfirmWithDefault(message, false)
}

// ConfirmWithDefault prompts with a yes/no question and the given default.
func (p *LivePrompter) ConfirmWithDefault(message string, defaultYes bool) bool {
	fmt.Fprint(p.out, message)
	response := p.readLine()
	if response == "" {
		return defaultYes
	}
	return response == "y" || response == "yes"
}

// Input prompts the user for free-text input and returns the response.
// If the user enters nothing, defaultValue is returned.
func (p *LivePrompter) Input(prompt string, defaultValue string) string {
	if defaultValue != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", prompt, defaultValue)
	} else {
		fmt.Fprintf(p.out, "%s: ", prompt)
	}
	response := p.readRawLine()
	if response == "" {
		return defaultValue
	}
	return response
}

// Select displays a numbered list of options and returns the selected index (0-based), or -1 if cancelled.
func (p *LivePrompter) Select(promptMsg string, options []Option) int {
	if len(options) == 0 {
		return -1
	}

	fmt.Fprintln(p.out, promptMsg)
	fmt.Fprintln(p.out)

	for i, opt := range options {
		if opt.Description != "" {
			fmt.Fprintf(p.out, "  %d. %-20s %s\n", i+1, opt.Label, opt.Description)
		} else {
			fmt.Fprintf(p.out, "  %d. %s\n", i+1, opt.Label)
		}
	}

	fmt.Fprintln(p.out)
	fmt.Fprintf(p.out, "Select [1-%d]: ", len(options))

	selection := p.readSelection()
	if selection < 1 || selection > len(options) {
		return -1
	}
	return selection - 1
}

// SelectWithGroups displays grouped options and returns the selected index (0-based across all groups), or -1 if cancelled.
func (p *LivePrompter) SelectWithGroups(promptMsg string, groups map[string][]Option, groupOrder []string) int {
	if len(groups) == 0 {
		return -1
	}

	fmt.Fprintln(p.out, promptMsg)
	fmt.Fprintln(p.out)

	index := 0
	for _, groupName := range groupOrder {
		options, ok := groups[groupName]
		if !ok || len(options) == 0 {
			continue
		}

		fmt.Fprintf(p.out, "%s:\n", groupName)
		for _, opt := range options {
			index++
			if opt.Description != "" {
				fmt.Fprintf(p.out, "  %d. %-20s %s\n", index, opt.Label, opt.Description)
			} else {
				fmt.Fprintf(p.out, "  %d. %s\n", index, opt.Label)
			}
		}
		fmt.Fprintln(p.out)
	}

	if index == 0 {
		return -1
	}

	fmt.Fprintf(p.out, "Select [1-%d]: ", index)

	selection := p.readSelection()
	if selection < 1 || selection > index {
		return -1
	}
	return selection - 1
}

// MultiSelect displays a numbered list of options and returns all selected
// indices (0-based). The user enters space-separated numbers; an empty line
// returns nil.
func (p *LivePrompter) MultiSelect(prompt string, options []Option) []int {
	if len(options) == 0 {
		return nil
	}

	fmt.Fprintln(p.out, prompt)
	fmt.Fprintln(p.out)

	for i, opt := range options {
		if opt.Description != "" {
			fmt.Fprintf(p.out, "  %d. %-30s %s\n", i+1, opt.Label, opt.Description)
		} else {
			fmt.Fprintf(p.out, "  %d. %s\n", i+1, opt.Label)
		}
	}

	fmt.Fprintln(p.out)
	fmt.Fprintf(p.out, "Select [1-%d, space-separated, empty to skip]: ", len(options))

	input := p.readRawLine()
	if input == "" {
		return nil
	}

	fields := strings.Fields(input)
	seen := make(map[int]bool)
	var indices []int
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > len(options) {
			fmt.Fprintf(p.out, "  Invalid selection: %s\n", f)
			return nil
		}
		idx := n - 1
		if !seen[idx] {
			seen[idx] = true
			indices = append(indices, idx)
		}
	}

	return indices
}
