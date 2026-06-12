//go:build darwin

package vfkit

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func listenTCP(port int) (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
}

// withLookupComm swaps the package-level comm lookup for the duration of a
// test, restoring it afterward.
func withLookupComm(t *testing.T, fn func(pid int) (string, error)) {
	t.Helper()
	prev := lookupComm
	lookupComm = fn
	t.Cleanup(func() { lookupComm = prev })
}

// deadPID spawns a trivial process, waits for it to exit, and returns its PID.
// The PID is guaranteed dead (and reaped) so kill/signal logic that runs
// against it can never harm an innocent process.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run helper process: %v", err)
	}
	return cmd.Process.Pid
}

func writePIDFile(t *testing.T, pid int) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "test.pid")
	if err := os.WriteFile(f, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// ---------- isVfkitProcess ----------

func TestIsVfkitProcess_Match(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "/usr/local/bin/vfkit", nil })
	if !isVfkitProcess(4242) {
		t.Error("isVfkitProcess should match a comm containing 'vfkit'")
	}
}

func TestIsVfkitProcess_WrongProcess(t *testing.T) {
	// A live PID whose comm is NOT vfkit (e.g. the test binary itself) must
	// not be treated as a vfkit process — this is the guard that stops us
	// killing an innocent process that reused a stale PID.
	withLookupComm(t, func(int) (string, error) { return "some-other-binary", nil })
	if isVfkitProcess(os.Getpid()) {
		t.Error("isVfkitProcess must be false for a non-vfkit comm")
	}
}

func TestIsVfkitProcess_LookupError(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "", os.ErrNotExist })
	if isVfkitProcess(999999) {
		t.Error("isVfkitProcess must be false when the comm lookup fails")
	}
}

// ---------- IsRunning ----------

func TestIsRunning_WrongProcessDoesNotCount(t *testing.T) {
	// PID file points at our own (alive) PID, but comm isn't vfkit. IsRunning
	// must report false rather than mistaking an unrelated live process for a
	// running VM.
	withLookupComm(t, func(int) (string, error) { return "go-test", nil })
	f := writePIDFile(t, os.Getpid())
	if IsRunning(f) {
		t.Error("IsRunning must be false when the live PID is not a vfkit process")
	}
}

func TestIsRunning_DeadPID(t *testing.T) {
	// Even if comm-lookup were to claim vfkit, a dead PID is not running.
	// Use a guaranteed-dead PID; lookupComm returns an error for it (ps fails).
	withLookupComm(t, func(int) (string, error) { return "", os.ErrNotExist })
	f := writePIDFile(t, deadPID(t))
	if IsRunning(f) {
		t.Error("IsRunning must be false for a dead PID")
	}
}

// ---------- StopVM / ForceStopVM stale-PID handling ----------

func TestStopVM_StalePIDFileRemoved(t *testing.T) {
	// PID file references a process that is not vfkit. StopVM must NOT signal
	// it; it should simply remove the stale PID file and return nil.
	called := false
	withLookupComm(t, func(int) (string, error) {
		called = true
		return "some-daemon", nil
	})
	f := writePIDFile(t, os.Getpid()) // our own live PID — must never be killed

	if err := StopVM(f); err != nil {
		t.Fatalf("StopVM() error: %v", err)
	}
	if !called {
		t.Error("StopVM should have consulted the comm lookup")
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("StopVM should have removed the stale PID file, stat err = %v", err)
	}
	// We are obviously still alive: StopVM did not kill the wrong process.
}

func TestForceStopVM_StalePIDFileRemoved(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "some-daemon", nil })
	f := writePIDFile(t, os.Getpid())

	if err := ForceStopVM(f); err != nil {
		t.Fatalf("ForceStopVM() error: %v", err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("ForceStopVM should have removed the stale PID file, stat err = %v", err)
	}
}

func TestStopVM_MissingPIDFile(t *testing.T) {
	if err := StopVM(filepath.Join(t.TempDir(), "nope.pid")); err == nil {
		t.Error("StopVM should error on a missing PID file (ReadPID fails)")
	}
}

// ---------- CleanupPIDFile ----------

func TestCleanupPIDFile_RemovesStale(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "", os.ErrNotExist })
	f := writePIDFile(t, deadPID(t))
	if err := CleanupPIDFile(f); err != nil {
		t.Fatalf("CleanupPIDFile() error: %v", err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("CleanupPIDFile should remove a stale PID file, stat err = %v", err)
	}
}

func TestCleanupPIDFile_RefusesRunning(t *testing.T) {
	// A live vfkit-looking process must block cleanup.
	withLookupComm(t, func(int) (string, error) { return "vfkit", nil })
	f := writePIDFile(t, os.Getpid())
	if err := CleanupPIDFile(f); err == nil {
		t.Error("CleanupPIDFile should refuse to remove a PID file for a running process")
	}
}

// ---------- restapi.go via httptest ----------

func httpToRESTfulURI(serverURL string) string {
	// Tests build a real http:// server; restBaseURL only rewrites tcp://,
	// so feed it a tcp:// form that maps back to the test server.
	return "tcp://" + serverURL[len("http://"):]
}

func TestVMState_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/vm/state" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"state":"VirtualMachineStateRunning","canStop":true}`))
	}))
	defer srv.Close()

	state, err := VMState(httpToRESTfulURI(srv.URL))
	if err != nil {
		t.Fatalf("VMState() error: %v", err)
	}
	if state != "VirtualMachineStateRunning" {
		t.Errorf("VMState() = %q, want running", state)
	}
}

func TestVMState_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := VMState(httpToRESTfulURI(srv.URL)); err == nil {
		t.Error("VMState() should error on a non-200 response")
	}
}

func TestVMState_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	if _, err := VMState(httpToRESTfulURI(srv.URL)); err == nil {
		t.Error("VMState() should error on malformed JSON")
	}
}

func TestRequestStop_SendsCorrectBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/vm/state" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		var body struct {
			State string `json:"state"`
		}
		if err := decodeJSON(r, &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.State != "Stop" {
			t.Errorf("state = %q, want Stop", body.State)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := RequestStop(httpToRESTfulURI(srv.URL)); err != nil {
		t.Fatalf("RequestStop() error: %v", err)
	}
}

func TestRequestHardStop_Body(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			State string `json:"state"`
		}
		_ = decodeJSON(r, &body)
		got = body.State
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := RequestHardStop(httpToRESTfulURI(srv.URL)); err != nil {
		t.Fatalf("RequestHardStop() error: %v", err)
	}
	if got != "HardStop" {
		t.Errorf("posted state = %q, want HardStop", got)
	}
}

func TestRequestStop_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadRequest)
	}))
	defer srv.Close()

	if err := RequestStop(httpToRESTfulURI(srv.URL)); err == nil {
		t.Error("RequestStop() should error on a non-200 response")
	}
}

func TestAllocateRESTPort_Usable(t *testing.T) {
	port, err := AllocateRESTPort()
	if err != nil {
		t.Fatalf("AllocateRESTPort() error: %v", err)
	}
	if port <= 0 || port > 65535 {
		t.Fatalf("AllocateRESTPort() = %d, want a valid port", port)
	}
	// The port must actually be bindable — AllocateRESTPort closed its
	// listener, so we can claim the same port immediately.
	ln, err := listenTCP(port)
	if err != nil {
		t.Fatalf("allocated port %d is not usable: %v", port, err)
	}
	_ = ln.Close()
}

// TestVerifyLive_RESTAnswers confirms that VerifyLive returns success as soon
// as the REST API answers, treating a serving process as definitively up.
func TestVerifyLive_RESTAnswers(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "vfkit", nil })
	f := writePIDFile(t, os.Getpid()) // our process stands in for a live vfkit

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"state":"VirtualMachineStateRunning"}`))
	}))
	defer srv.Close()

	start := time.Now()
	if err := VerifyLive(f, httpToRESTfulURI(srv.URL), 5*time.Second); err != nil {
		t.Fatalf("VerifyLive() error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("VerifyLive() took %v, expected to return promptly once REST answered", elapsed)
	}
}
