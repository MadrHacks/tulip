package tlsdecrypt

// These tests use Go's own crypto/tls as the *encryption oracle*: we drive a
// real TLS handshake + data exchange over a recording connection, capture the
// wire bytes and the NSS key log Go emits, then feed both into our passive
// decryptor and assert we recover the exact plaintext. This validates record
// framing, key-log lookup, the copied key schedule, AEAD, sequence numbers and
// the TLS 1.3 handshake→application secret transition end-to-end, with no
// network fixtures or external tools.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"go-importer/internal/pkg/db"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"test.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// recordConn captures both directions of the wire from the client's side:
// everything the client writes is client→server, everything it reads is
// server→client.
type recordConn struct {
	net.Conn
	c2s *bytes.Buffer
	s2c *bytes.Buffer
}

func (r *recordConn) Write(b []byte) (int, error) {
	n, err := r.Conn.Write(b)
	r.c2s.Write(b[:n])
	return n, err
}

func (r *recordConn) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	r.s2c.Write(b[:n])
	return n, err
}

type exchange struct {
	items   []db.FlowItem
	keylog  string
	request []byte
	reply   []byte
	suite   uint16
	version uint16
}

// runExchange performs a TLS handshake and a request/response, returning the
// captured wire bytes (as one client item + one server item), the key log, and
// the expected plaintexts.
func runExchange(t *testing.T, minVer, maxVer uint16, suites []uint16) exchange {
	t.Helper()
	cert := selfSignedCert(t)
	request := []byte("GET /flag HTTP/1.1\r\nHost: test.local\r\n\r\n")
	reply := []byte("HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\nflag{decrypted_ok}")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	var negotiated uint16
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer raw.Close()
		sconn := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   minVer,
			MaxVersion:   maxVer,
			CipherSuites: suites,
		})
		if err := sconn.Handshake(); err != nil {
			serverDone <- err
			return
		}
		buf := make([]byte, len(request))
		if _, err := io.ReadFull(sconn, buf); err != nil {
			serverDone <- err
			return
		}
		if _, err := sconn.Write(reply); err != nil {
			serverDone <- err
			return
		}
		negotiated = sconn.ConnectionState().CipherSuite
		// Give the client a moment to read before tearing down.
		time.Sleep(20 * time.Millisecond)
		serverDone <- nil
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c2s := &bytes.Buffer{}
	s2c := &bytes.Buffer{}
	rc := &recordConn{Conn: raw, c2s: c2s, s2c: s2c}

	keylog := &bytes.Buffer{}
	client := tls.Client(rc, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         minVer,
		MaxVersion:         maxVer,
		CipherSuites:       suites,
		KeyLogWriter:       keylog,
		ServerName:         "test.local",
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	replyBuf := make([]byte, len(reply))
	if _, err := io.ReadFull(client, replyBuf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	state := client.ConnectionState()
	client.Close()
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}

	now := time.Now()
	items := []db.FlowItem{
		{Kind: "raw", From: "c", Data: append([]byte(nil), c2s.Bytes()...), Time: now},
		{Kind: "raw", From: "s", Data: append([]byte(nil), s2c.Bytes()...), Time: now},
	}
	_ = negotiated
	return exchange{
		items:   items,
		keylog:  keylog.String(),
		request: request,
		reply:   reply,
		suite:   state.CipherSuite,
		version: state.Version,
	}
}

func collect(items []db.FlowItem, from string) []byte {
	var out []byte
	for _, it := range items {
		if it.From == from && it.Kind == DecryptedKind {
			out = append(out, it.Data...)
		}
	}
	return out
}

func TestDecryptTLS(t *testing.T) {
	cases := []struct {
		name   string
		minVer uint16
		maxVer uint16
		suites []uint16
	}{
		{"tls12-aes128-gcm", tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}},
		{"tls12-aes256-gcm", tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}},
		{"tls12-chacha20", tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305}},
		{"tls13", tls.VersionTLS13, tls.VersionTLS13, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex := runExchange(t, tc.minVer, tc.maxVer, tc.suites)
			t.Logf("negotiated version=0x%04x suite=0x%04x", ex.version, ex.suite)

			keys := newKeyLogFromString(ex.keylog)
			out := Process(keys, ex.items, -1, -1)
			if out.Status != StatusDecrypted {
				t.Fatalf("status = %v, want StatusDecrypted", out.Status)
			}

			gotReq := collect(out.Items, "c")
			if !bytes.Equal(gotReq, ex.request) {
				t.Errorf("client plaintext mismatch:\n got %q\nwant %q", gotReq, ex.request)
			}
			gotReply := collect(out.Items, "s")
			if !bytes.Equal(gotReply, ex.reply) {
				t.Errorf("server plaintext mismatch:\n got %q\nwant %q", gotReply, ex.reply)
			}
		})
	}
}

// TestDecryptChunked splits each direction's wire bytes into many small items
// to exercise TLS records that span FlowItem boundaries (and the leftover
// buffer).
func TestDecryptChunked(t *testing.T) {
	ex := runExchange(t, tls.VersionTLS13, tls.VersionTLS13, nil)

	var chunked []db.FlowItem
	for _, it := range ex.items {
		data := it.Data
		for len(data) > 0 {
			n := 7
			if n > len(data) {
				n = len(data)
			}
			chunked = append(chunked, db.FlowItem{Kind: "raw", From: it.From, Data: data[:n], Time: it.Time})
			data = data[n:]
		}
	}

	keys := newKeyLogFromString(ex.keylog)
	out := Process(keys, chunked, -1, -1)
	if out.Status != StatusDecrypted {
		t.Fatalf("status = %v, want StatusDecrypted for chunked input", out.Status)
	}
	if got := collect(out.Items, "s"); !bytes.Equal(got, ex.reply) {
		t.Errorf("chunked server plaintext mismatch:\n got %q\nwant %q", got, ex.reply)
	}
}

// TestDecryptNoKeys verifies graceful no-op when secrets are missing.
// TestProcessStatus checks the classification that drives retroactive
// decryption: a TLS flow with no keys must report NeedKey (so it gets queued)
// and expose the client_random (so a later key can find it); with keys it must
// report Decrypted; cleartext must be NotTLS.
func TestProcessStatus(t *testing.T) {
	ex := runExchange(t, tls.VersionTLS13, tls.VersionTLS13, nil)

	// Expected client_random is the second field of any key-log line.
	var wantCR []byte
	for _, line := range splitLines(ex.keylog) {
		parts := bytes.Fields([]byte(line))
		if len(parts) == 3 {
			wantCR = mustHex(t, string(parts[1]))
			break
		}
	}

	// No keys → NeedKey, with the client_random surfaced for later matching.
	empty := newKeyLogFromString("")
	got := Process(empty, ex.items, -1, -1)
	if got.Status != StatusNeedKey {
		t.Fatalf("no-key status = %v, want StatusNeedKey", got.Status)
	}
	if !bytes.Equal(got.ClientRandom, wantCR) {
		t.Errorf("client_random = %x, want %x", got.ClientRandom, wantCR)
	}

	// With keys → Decrypted.
	keys := newKeyLogFromString(ex.keylog)
	if got := Process(keys, ex.items, -1, -1); got.Status != StatusDecrypted {
		t.Errorf("with-key status = %v, want StatusDecrypted", got.Status)
	}

	// Cleartext → NotTLS.
	clear := []db.FlowItem{
		{Kind: "raw", From: "c", Data: []byte("GET / HTTP/1.1\r\n\r\n")},
		{Kind: "raw", From: "s", Data: []byte("HTTP/1.1 200 OK\r\n\r\nhi")},
	}
	if got := Process(keys, clear, -1, -1); got.Status != StatusNotTLS {
		t.Errorf("cleartext status = %v, want StatusNotTLS", got.Status)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestDecryptNonTLS verifies a cleartext flow is ignored.
func TestDecryptNonTLS(t *testing.T) {
	keys := newKeyLogFromString("CLIENT_RANDOM " +
		"0000000000000000000000000000000000000000000000000000000000000000 " +
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	items := []db.FlowItem{
		{Kind: "raw", From: "c", Data: []byte("GET / HTTP/1.1\r\n\r\n")},
		{Kind: "raw", From: "s", Data: []byte("HTTP/1.1 200 OK\r\n\r\nhi")},
	}
	if out := Process(keys, items, -1, -1); out.Status != StatusNotTLS {
		t.Errorf("status = %v, want StatusNotTLS for cleartext flow", out.Status)
	}
}
