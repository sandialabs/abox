//go:build darwin

package vfkit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/logging"
)

// vmStateResponse represents the JSON response from vfkit's GET /vm/state endpoint.
type vmStateResponse struct {
	State    string `json:"state"`
	CanStart bool   `json:"canStart"`
	CanStop  bool   `json:"canStop"`
	CanPause bool   `json:"canPause"`
}

// vmStateRequest represents the JSON body for vfkit's POST /vm/state endpoint.
type vmStateRequest struct {
	State string `json:"state"`
}

// httpClient is a shared HTTP client with a short timeout for local REST calls.
var httpClient = &http.Client{Timeout: 5 * time.Second}

// restBaseURL converts a vfkit --restful-uri value (e.g., "tcp://localhost:12345")
// to an HTTP base URL (e.g., "http://localhost:12345").
func restBaseURL(restfulURI string) string {
	return strings.Replace(restfulURI, "tcp://", "http://", 1)
}

// doRequest executes an HTTP request with a background context.
func doRequest(method, url string, body []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return httpClient.Do(req)
}

// VMState queries the vfkit REST API for the current VM state.
// Returns the state string, e.g. "VirtualMachineStateRunning" or "VirtualMachineStateStopped".
func VMState(restfulURI string) (string, error) {
	url := restBaseURL(restfulURI) + "/vm/state"

	resp, err := doRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("query vfkit state: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read vfkit state response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vfkit state returned %d: %s", resp.StatusCode, string(respBody))
	}

	var state vmStateResponse
	if err := json.Unmarshal(respBody, &state); err != nil {
		return "", fmt.Errorf("parse vfkit state: %w", err)
	}

	return state.State, nil
}

// RequestStop asks vfkit to gracefully stop the VM via its REST API.
// This triggers an ACPI shutdown, equivalent to pressing the power button.
func RequestStop(restfulURI string) error {
	return postVMState(restfulURI, "Stop", "graceful stop")
}

// RequestHardStop asks vfkit to forcefully stop the VM via its REST API.
func RequestHardStop(restfulURI string) error {
	return postVMState(restfulURI, "HardStop", "hard stop")
}

// postVMState sends a state change request to the vfkit REST API.
func postVMState(restfulURI, state, description string) error {
	url := restBaseURL(restfulURI) + "/vm/state"

	reqBody, err := json.Marshal(vmStateRequest{State: state})
	if err != nil {
		return fmt.Errorf("marshal %s request: %w", description, err)
	}

	logging.Debug("requesting vfkit "+description, "uri", restfulURI)

	resp, err := doRequest(http.MethodPost, url, reqBody)
	if err != nil {
		return fmt.Errorf("request vfkit %s: %w", description, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vfkit %s returned %d: %s", description, resp.StatusCode, string(body))
	}

	return nil
}

// AllocateRESTPort finds an available TCP port for the vfkit REST API.
// It binds to :0, reads the assigned port, and closes the listener.
func AllocateRESTPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("allocate REST port: %w", err)
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return 0, fmt.Errorf("unexpected listener address type: %T", listener.Addr())
	}
	port := tcpAddr.Port
	_ = listener.Close()
	return port, nil
}
