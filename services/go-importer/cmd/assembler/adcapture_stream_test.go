// Copyright 2026 MadrHacks. Apache-2.0.

package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestAdCapturePayloadDecode_GoldenBytes verifies the tulip-side decoder
// matches the byte layout that ad-capture's CustomBlockPayloadV1.Marshal()
// produces. The golden bytes below are constructed by hand from the same
// schema (see services/ad-capture/internal/output/writers/pcapng_broker.go).
// If either side changes the layout, this test breaks loudly — the contract
// spans two repos, so version it.
func TestAdCapturePayloadDecode_GoldenBytes(t *testing.T) {
	wantPayload := []byte("GET /flag HTTP/1.1\r\n\r\n")

	var b []byte
	b = append(b, 1)                    // Version
	b = append(b, 4)                    // IPFamily (v4)
	b = append(b, 0)                    // Direction (c->s)
	b = append(b, 0)                    // Reserved
	b = append(b, le32(0x1234)...)      // Pid
	b = append(b, fix16("curl-ad")...)  // Comm
	b = append(b, fix16Bytes(10, 0, 0, 1)...)
	b = append(b, fix16Bytes(172, 17, 0, 2)...)
	b = append(b, le16(51234)...) // SrcPort
	b = append(b, le16(443)...)   // DstPort
	b = append(b, le32(0x0304)...) // TLSVersion
	b = append(b, le64(1779177600000000000)...)
	b = append(b, le32(uint32(len(wantPayload)))...)
	b = append(b, wantPayload...)

	if len(b) != adCapturePayloadHeaderSize+len(wantPayload) {
		t.Fatalf("constructed payload len = %d, want %d", len(b),
			adCapturePayloadHeaderSize+len(wantPayload))
	}

	got, err := decodeAdCapturePayload(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Version != 1 || got.IPFamily != 4 || got.Direction != 0 {
		t.Errorf("scalar mismatch: %+v", got)
	}
	if got.Pid != 0x1234 || got.SrcPort != 51234 || got.DstPort != 443 {
		t.Errorf("tuple mismatch: pid=%d sport=%d dport=%d", got.Pid, got.SrcPort, got.DstPort)
	}
	if got.TLSVersion != 0x0304 {
		t.Errorf("tls version = %#x", got.TLSVersion)
	}
	if got.Timestamp != 1779177600000000000 {
		t.Errorf("timestamp = %d", got.Timestamp)
	}
	if !bytes.Equal(got.Payload, wantPayload) {
		t.Errorf("payload = %q, want %q", got.Payload, wantPayload)
	}
}

func le16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}
func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
func le64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}
func fix16(s string) []byte {
	b := make([]byte, 16)
	copy(b, s)
	return b
}
func fix16Bytes(vals ...byte) []byte {
	b := make([]byte, 16)
	copy(b, vals)
	return b
}
