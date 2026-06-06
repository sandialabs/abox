// Package iostreams provides centralized I/O stream management.
// During TUI execution, SetOutput redirects Out and ErrOut to the TUI's
// ProgressWriter so that fmt.Fprintf(io.Out, ...) appears in the TUI log
// panel instead of corrupting the inline display.
package iostreams

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// IOStreams holds the standard I/O streams for a CLI session.
type IOStreams struct {
	mu sync.Mutex

	In     io.Reader
	Out    io.Writer
	ErrOut io.Writer

	isTerminal bool

	origOut    io.Writer
	origErrOut io.Writer

	pagerCmd    *exec.Cmd
	pagerPipe   io.WriteCloser
	pagerOrigIO *IOStreams // saved streams before pager
}

// Test returns an IOStreams backed by in-memory buffers for use in tests.
// The returned buffers capture stdin, stdout, and stderr output respectively.
func Test() (*IOStreams, *bytes.Buffer, *bytes.Buffer, *bytes.Buffer) {
	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	return &IOStreams{
		In:     stdin,
		Out:    stdout,
		ErrOut: stderr,
	}, stdin, stdout, stderr
}

// New returns an IOStreams wired to the real terminal.
func New() *IOStreams {
	s := &IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}
	if f, ok := s.Out.(*os.File); ok {
		if fi, err := f.Stat(); err == nil {
			s.isTerminal = (fi.Mode() & os.ModeCharDevice) != 0
		}
	}
	return s
}

// IsTerminal reports whether Out is connected to a terminal.
func (s *IOStreams) IsTerminal() bool {
	return s.isTerminal
}

// SetOutput redirects both Out and ErrOut to w and saves the originals
// so they can be restored with RestoreOutput.
func (s *IOStreams) SetOutput(w io.Writer) {
	s.SetOutputSplit(w, w)
}

// SetOutputSplit redirects Out and ErrOut to separate writers and saves the
// originals so they can be restored with RestoreOutput.
func (s *IOStreams) SetOutputSplit(out, errOut io.Writer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.origOut = s.Out
	s.origErrOut = s.ErrOut
	s.Out = out
	s.ErrOut = errOut
}

// RestoreOutput restores Out and ErrOut to the values saved by SetOutput.
// It is a no-op if SetOutput was never called.
func (s *IOStreams) RestoreOutput() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origOut != nil {
		s.Out = s.origOut
		s.ErrOut = s.origErrOut
		s.origOut = nil
		s.origErrOut = nil
	}
}

// StartPager starts an external pager process (e.g. less) and redirects Out
// to it. The pager command is determined by ABOX_PAGER, PAGER, or defaults
// to "less". Set ABOX_PAGER="" to disable paging.
//
// If stdout is not a terminal, the pager is not started.
// Call StopPager when output is complete.
func (s *IOStreams) StartPager() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isTerminal {
		return
	}

	var pagerCmd string
	for _, envVar := range []string{"ABOX_PAGER", "PAGER"} {
		p, ok := os.LookupEnv(envVar)
		if !ok {
			continue
		}
		if p == "" {
			return // explicitly disabled
		}
		pagerCmd = p
		break
	}
	if pagerCmd == "" {
		pagerCmd = "less"
	}

	// Explicitly disabled
	if pagerCmd == "cat" {
		return
	}

	parts := strings.Fields(pagerCmd)
	if len(parts) == 0 {
		return
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdout = s.Out
	cmd.Stderr = s.ErrOut

	// Always set LESS=FRX (quit-if-one-screen, raw control chars,
	// no init) so that paging behaves correctly regardless of the
	// user's shell LESS setting.
	cmd.Env = append(os.Environ(), "LESS=FRX")

	pipe, err := cmd.StdinPipe()
	if err != nil {
		return
	}

	if err := cmd.Start(); err != nil {
		return
	}

	s.pagerCmd = cmd
	s.pagerPipe = pipe
	s.pagerOrigIO = &IOStreams{Out: s.Out, ErrOut: s.ErrOut}
	s.Out = pipe
}

// StopPager closes the pager's input pipe and waits for it to exit.
// It restores Out to the original writer. It is a no-op if no pager is running.
func (s *IOStreams) StopPager() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pagerPipe == nil {
		return
	}

	_ = s.pagerPipe.Close()
	_ = s.pagerCmd.Wait()

	s.Out = s.pagerOrigIO.Out
	s.ErrOut = s.pagerOrigIO.ErrOut
	s.pagerCmd = nil
	s.pagerPipe = nil
	s.pagerOrigIO = nil
}
