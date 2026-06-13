package noisecat

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gedigi/noisecat/pkg/transport/noisesocket"
)

const (
	protoNN = "Noise_NN_25519_AESGCM_SHA256"
	protoXX = "Noise_XX_25519_AESGCM_SHA256"
)

// runFullStackNeg starts a noisesocket listener with the server Config's
// negotiation options and dials it with the client Config's, then
// round-trips a payload through the echo server. Returns the client-side
// error (nil on success).
func runFullStackNeg(t *testing.T, serverCfg, clientCfg Config) error {
	t.Helper()

	srv := Noisecat{Config: &serverCfg, Log: Verbose(false)}
	cli := Noisecat{Config: &clientCfg, Log: Verbose(false)}
	sOpts := srv.transportOptions()
	cOpts := cli.transportOptions()
	if sOpts.Negotiation == nil || cOpts.Negotiation == nil {
		t.Fatal("negotiation should be enabled on both sides")
	}

	tp := noisesocket.New()
	l, err := tp.Listen("tcp", "127.0.0.1:0", nil, sOpts)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.Copy(conn, conn)
	}()

	addr := l.Addr().(*net.TCPAddr)
	conn, err := tp.Dial("tcp", "127.0.0.1:"+strconv.Itoa(addr.Port), "", nil, cOpts)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	want := []byte("full-stack-negotiated-payload")
	if _, err := conn.Write(want); err != nil {
		return err
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, want)
	}
	return nil
}

func TestFullStackNegotiateAccept(t *testing.T) {
	server := Config{Transport: "noisesocket", Listen: true, NSSupport: protoNN + "," + protoXX}
	client := Config{Transport: "noisesocket", Protocol: protoNN}
	// Client must opt into negotiation; propose NN which the server supports.
	client.NSFallback = protoXX
	if err := runFullStackNeg(t, server, client); err != nil {
		t.Fatalf("accept end-to-end failed: %v", err)
	}
}

func TestFullStackNegotiateRetry(t *testing.T) {
	server := Config{Transport: "noisesocket", Listen: true, NSSupport: protoXX, NSPolicy: "retry"}
	client := Config{Transport: "noisesocket", Protocol: protoNN, NSFallback: protoXX}
	if err := runFullStackNeg(t, server, client); err != nil {
		t.Fatalf("retry end-to-end failed: %v", err)
	}
}

func TestFullStackNegotiateSwitch(t *testing.T) {
	server := Config{Transport: "noisesocket", Listen: true, NSSupport: protoXX, NSPolicy: "switch"}
	client := Config{Transport: "noisesocket", Protocol: protoNN, NSFallback: protoXX}
	if err := runFullStackNeg(t, server, client); err != nil {
		t.Fatalf("switch end-to-end failed: %v", err)
	}
}

func TestNegotiationConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name:    "neg without noisesocket",
			cfg:     Config{Protocol: protoNN, Listen: true, NSSupport: protoNN},
			wantErr: "require -transport noisesocket",
		},
		{
			name:    "fallback on listener",
			cfg:     Config{Protocol: protoNN, Transport: "noisesocket", Listen: true, NSFallback: protoXX, NSSupport: protoNN},
			wantErr: "client option",
		},
		{
			name:    "support on client",
			cfg:     Config{Protocol: protoNN, Transport: "noisesocket", NSSupport: protoNN},
			wantErr: "listener option",
		},
		{
			name:    "bad policy",
			cfg:     Config{Protocol: protoNN, Transport: "noisesocket", Listen: true, NSSupport: protoNN, NSPolicy: "bogus"},
			wantErr: "invalid -ns-policy",
		},
		{
			name: "valid client",
			cfg:  Config{Protocol: protoNN, Transport: "noisesocket", NSFallback: protoXX},
		},
		{
			name: "valid listener",
			cfg:  Config{Protocol: protoNN, Transport: "noisesocket", Listen: true, NSSupport: protoXX, NSPolicy: "switch"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			_, err := cfg.ParseConfig()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v does not contain %q", err, tc.wantErr)
			}
		})
	}
}
