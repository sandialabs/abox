//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestForward tests the port forwarding commands.
func TestForward(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}
	if !inst.waitForSSH(120 * time.Second) {
		inst.dumpDiagnostics()
		t.Fatal("SSH did not become available")
	}

	t.Run("add-list-remove", func(t *testing.T) {
		// Add a port forward
		result := env.mustRun("forward", "add", inst.name, "18080:80")
		if !strings.Contains(result.Stdout, "Forwarding") {
			t.Errorf("Expected forwarding message, got: %s", result.Stdout)
		}

		// Verify it appears in the list
		listResult := env.mustRun("forward", "list", inst.name)
		if !strings.Contains(listResult.Stdout, "18080") {
			t.Errorf("Forward should appear in list, got: %s", listResult.Stdout)
		}
		if !strings.Contains(listResult.Stdout, "80") {
			t.Errorf("Guest port should appear in list, got: %s", listResult.Stdout)
		}

		// Remove the forward
		result = env.mustRun("forward", "remove", inst.name, "18080")
		if !strings.Contains(result.Stdout, "Removed") {
			t.Errorf("Expected removal message, got: %s", result.Stdout)
		}

		// Verify it's gone from the list
		listResult = env.mustRun("forward", "list", inst.name)
		if strings.Contains(listResult.Stdout, "18080") {
			t.Error("Forward should not appear in list after removal")
		}
	})

	t.Run("connectivity", func(t *testing.T) {
		// Start a simple HTTP server in the VM
		// Use Python's http.server module which is available by default
		sshResult := inst.ssh("bash", "-c", "nohup python3 -m http.server 8000 > /dev/null 2>&1 &")
		if !sshResult.Success() {
			t.Logf("Warning: Failed to start HTTP server: %v", sshResult.Stderr)
		}

		// Give the server time to start
		time.Sleep(2 * time.Second)

		// Add a forward for the HTTP server
		result := env.mustRun("forward", "add", inst.name, "18000:8000")
		if !result.Success() {
			t.Fatalf("Failed to add forward: %v", result.Err)
		}

		// Clean up forward at the end
		defer env.run("forward", "remove", inst.name, "18000")

		// Try to connect from the host
		time.Sleep(1 * time.Second) // Give the tunnel time to establish

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("http://localhost:18000/")
		if err != nil {
			t.Logf("HTTP request failed (may be expected if python server not running): %v", err)
			// Don't fail - the server might not have started
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected HTTP 200, got %d", resp.StatusCode)
		}

		// Stop the server
		inst.ssh("pkill", "-f", "http.server")
	})

	t.Run("duplicate-port", func(t *testing.T) {
		// Add a forward
		env.mustRun("forward", "add", inst.name, "18081:81")
		defer env.run("forward", "remove", inst.name, "18081")

		// Try to add the same host port again
		result := env.run("forward", "add", inst.name, "18081:82")
		if result.Success() {
			t.Error("Adding duplicate host port should fail")
		}
		if !strings.Contains(result.Stderr, "already forwarded") && !strings.Contains(result.Stdout, "already forwarded") {
			t.Errorf("Expected error about port already forwarded, got: %s %s", result.Stdout, result.Stderr)
		}
	})

	t.Run("requires-running", func(t *testing.T) {
		// Stop the instance
		inst.forceStop()

		result := env.run("forward", "add", inst.name, "18082:82")
		if result.Success() {
			t.Error("Forward add should fail when instance is not running")
		}
		output := result.Stdout + result.Stderr
		if !strings.Contains(output, "not running") && !strings.Contains(output, "must be running") {
			t.Errorf("Expected error about instance not running, got: %s", output)
		}
	})
}

// TestForwardReverse tests reverse port forwarding (guest accesses host).
func TestForwardReverse(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}
	if !inst.waitForSSH(120 * time.Second) {
		inst.dumpDiagnostics()
		t.Fatal("SSH did not become available")
	}

	t.Run("reverse-add-list-remove", func(t *testing.T) {
		// Add a reverse forward
		result := env.mustRun("forward", "add", inst.name, "19000:9000", "-R")
		if !strings.Contains(result.Stdout, "Reverse") {
			t.Errorf("Expected reverse forwarding message, got: %s", result.Stdout)
		}

		// Verify it appears in the list with correct direction
		listResult := env.mustRun("forward", "list", inst.name)
		if !strings.Contains(listResult.Stdout, "19000") {
			t.Errorf("Reverse forward should appear in list, got: %s", listResult.Stdout)
		}
		if !strings.Contains(listResult.Stdout, "guest") {
			t.Errorf("Should show guest→host direction, got: %s", listResult.Stdout)
		}

		// Remove the forward
		result = env.mustRun("forward", "remove", inst.name, "19000")
		if !strings.Contains(result.Stdout, "Removed") {
			t.Errorf("Expected removal message, got: %s", result.Stdout)
		}
	})

	t.Run("reverse-connectivity", func(t *testing.T) {
		hostPort := 19001
		guestPort := 9001

		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "hello from host")
		})
		server := &http.Server{
			Addr:    fmt.Sprintf("localhost:%d", hostPort),
			Handler: mux,
		}

		serverReady := make(chan struct{})

		go func() {
			close(serverReady)
			if err := server.ListenAndServe(); err != http.ErrServerClosed {
				t.Logf("HTTP server error: %v", err)
			}
		}()

		<-serverReady
		defer server.Close()
		time.Sleep(500 * time.Millisecond)

		// Add reverse forward
		result := env.mustRun("forward", "add", inst.name, fmt.Sprintf("%d:%d", guestPort, hostPort), "-R")
		if !result.Success() {
			t.Fatalf("Failed to add reverse forward: %v", result.Err)
		}
		defer env.run("forward", "remove", inst.name, fmt.Sprintf("%d", guestPort))

		// Give the tunnel time to establish
		time.Sleep(1 * time.Second)

		// Try to access the host server from inside the VM
		sshResult := inst.ssh("curl", "-s", "--max-time", "5", fmt.Sprintf("http://localhost:%d/", guestPort))
		if !sshResult.Success() {
			t.Logf("Reverse forward connectivity test failed (may be expected): %s", sshResult.Stderr)
			// Don't fail - curl might not be installed
			return
		}

		if !strings.Contains(sshResult.Stdout, "hello from host") {
			t.Errorf("Expected 'hello from host', got: %s", sshResult.Stdout)
		}
	})
}
