package tlsdecrypt

// TLS record framing and minimal plaintext-handshake parsing. We do our own
// bounded parsing instead of gopacket's layers.TLS (which only handles ClientHello
// and can panic on truncated input); malformed input here yields a clean stop.

import (
	"golang.org/x/crypto/cryptobyte"
)

// tlsRecord is a single TLS record (still encrypted for app-data/handshake
// once the cipher is active).
type tlsRecord struct {
	Type    uint8
	Version uint16
	Payload []byte
}

const maxRecordPayload = 1 << 14 // 16384 plaintext, plus AEAD expansion; we allow a bit more below

// parseRecords splits a byte stream into complete TLS records, returning any
// trailing partial record as rest. An over-long declared length (a gap or
// non-TLS data) stops parsing rather than reading out of bounds.
func parseRecords(data []byte) (records []tlsRecord, rest []byte) {
	for len(data) >= 5 {
		typ := data[0]
		version := uint16(data[1])<<8 | uint16(data[2])
		length := int(data[3])<<8 | int(data[4])
		// Sanity bound: TLS records can't exceed 2^14 + 256 (padding/expansion).
		if length > maxRecordPayload+2048 {
			// Framing is hopelessly off (likely a gap or non-TLS data); stop.
			return records, nil
		}
		if len(data) < 5+length {
			// Incomplete final record.
			return records, data
		}
		records = append(records, tlsRecord{
			Type:    typ,
			Version: version,
			Payload: data[5 : 5+length],
		})
		data = data[5+length:]
	}
	return records, data
}

// looksLikeClientHello reports whether the first bytes of a client→server
// stream begin a TLS handshake ClientHello record. Cheap sniff used to decide
// whether a flow is worth attempting to decrypt.
func looksLikeClientHello(data []byte) bool {
	// 0x16 = handshake, 0x03 0x0x = TLS version, then handshake type 0x01.
	return len(data) >= 6 && data[0] == recordTypeHandshake && data[1] == 0x03 && data[5] == handshakeTypeClientHello
}

// handshakeInfo holds the fields we extract from the plaintext handshake.
type handshakeInfo struct {
	clientRandom []byte
	serverRandom []byte
	cipherSuite  uint16
	tls13        bool
}

// firstHandshakeMessage concatenates the leading plaintext handshake records and
// returns the body (excluding the 4-byte header) of the first message.
func firstHandshakeMessage(records []tlsRecord) (msgType uint8, body []byte, ok bool) {
	var hs []byte
	for _, r := range records {
		if r.Type != recordTypeHandshake {
			// Once we leave plaintext handshake records, stop accumulating.
			break
		}
		hs = append(hs, r.Payload...)
	}
	s := cryptobyte.String(hs)
	var t uint8
	if !s.ReadUint8(&t) {
		return 0, nil, false
	}
	var b cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&b) {
		return 0, nil, false
	}
	return t, []byte(b), true
}

// parseClientHello extracts client_random from a ClientHello body
// (RFC 8446 Section 4.1.2 / RFC 5246 Section 7.4.1.2). We only need the random;
// it's the lookup key into the key log.
func parseClientHello(body []byte) (random []byte, ok bool) {
	s := cryptobyte.String(body)
	var legacyVersion uint16
	if !s.ReadUint16(&legacyVersion) {
		return nil, false
	}
	random = make([]byte, 32)
	if !s.CopyBytes(random) {
		return nil, false
	}
	return random, true
}

// parseServerHello extracts server_random, the negotiated cipher suite, and
// whether the negotiated version is TLS 1.3 (signalled by a supported_versions
// extension carrying 0x0304; legacy_version stays 0x0303 in both 1.2 and 1.3).
func parseServerHello(body []byte) (random []byte, cipherSuite uint16, tls13 bool, ok bool) {
	s := cryptobyte.String(body)
	var legacyVersion uint16
	if !s.ReadUint16(&legacyVersion) {
		return nil, 0, false, false
	}
	random = make([]byte, 32)
	if !s.CopyBytes(random) {
		return nil, 0, false, false
	}
	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return nil, 0, false, false
	}
	if !s.ReadUint16(&cipherSuite) {
		return nil, 0, false, false
	}
	var compressionMethod uint8
	if !s.ReadUint8(&compressionMethod) {
		return nil, 0, false, false
	}
	if s.Empty() {
		return random, cipherSuite, false, true
	}
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return random, cipherSuite, false, true
	}
	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			break
		}
		if extType == 43 { // supported_versions
			var selected uint16
			if extData.ReadUint16(&selected) && selected == versionTLS13 {
				tls13 = true
			}
		}
	}
	return random, cipherSuite, tls13, true
}
