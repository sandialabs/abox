//go:build darwin

package vmnet

import (
	"fmt"
	"strings"
	"testing"
)

const sampleIfconfig = `lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
	inet 127.0.0.1 netmask 0xff000000
	inet6 ::1 prefixlen 128
	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
	nd6 options=201<PERFORMNUD,DAD>
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
	ether 14:98:77:ab:cd:ef
	inet 10.0.1.42 netmask 0xffffff00 broadcast 10.0.1.255
	media: autoselect
	status: active
bridge100: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500
	options=3<RXCSUM,TXCSUM>
	ether 4a:00:6d:12:34:56
	inet 192.168.64.1 netmask 0xffffff00 broadcast 192.168.64.255
	Configuration:
		id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
		maxage 0 holdcnt 0 proto stp maxaddr 100 timeout 1200
		root id 0:0:0:0:0:0 priority 0 ifcost 0 port 0
	member: vmenet0 flags=3<LEARNING,DISCOVER>
	        ifmaxaddr 0 port 18 priority 0 path cost 0
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active
`

const sampleIfconfigNoBridge = `lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 14:98:77:ab:cd:ef
	inet 10.0.1.42 netmask 0xffffff00 broadcast 10.0.1.255
`

const sampleIfconfigCustomSubnet = `lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
bridge100: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500
	ether 4a:00:6d:12:34:56
	inet 192.168.100.1 netmask 0xffffff00 broadcast 192.168.100.255
`

func TestParseGatewayFromIfconfig(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "standard vmnet bridge",
			input: sampleIfconfig,
			want:  "192.168.64.1",
		},
		{
			name:    "no bridge interface",
			input:   sampleIfconfigNoBridge,
			wantErr: true,
		},
		{
			name:  "custom vmnet subnet",
			input: sampleIfconfigCustomSubnet,
			want:  "192.168.100.1",
		},
		{
			name:    "empty output",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGatewayFromIfconfig(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectGateway(t *testing.T) {
	t.Run("uses ifconfig function", func(t *testing.T) {
		gw, err := detectGateway(func() (string, error) {
			return sampleIfconfig, nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gw != "192.168.64.1" {
			t.Errorf("got %q, want %q", gw, "192.168.64.1")
		}
	})

	t.Run("returns error on ifconfig failure", func(t *testing.T) {
		_, err := detectGateway(func() (string, error) {
			return "", fmt.Errorf("command not found")
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestSplitInterfaceBlocks(t *testing.T) {
	blocks := splitInterfaceBlocks(sampleIfconfig)
	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d", len(blocks))
	}
	if !strings.HasPrefix(blocks[0], "lo0:") {
		t.Errorf("block 0 should start with lo0:, got %q", blocks[0][:10])
	}
	if !strings.HasPrefix(blocks[1], "en0:") {
		t.Errorf("block 1 should start with en0:, got %q", blocks[1][:10])
	}
	if !strings.HasPrefix(blocks[2], "bridge100:") {
		t.Errorf("block 2 should start with bridge100:, got %q", blocks[2][:15])
	}
}
