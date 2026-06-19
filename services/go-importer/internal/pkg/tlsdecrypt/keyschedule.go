package tlsdecrypt

// Key-schedule helpers copied from Go's crypto/tls (key_schedule.go, prf.go) and
// crypto/internal/fips140/tls13, which aren't importable. BSD-3-Clause (Go LICENSE).
// Secrets come from the key log, so only the key/IV expansion side is needed.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

const aeadNonceLength = 12

// TLS record content types (RFC 8446 Section 5.1 / RFC 5246).
const (
	recordTypeChangeCipherSpec uint8 = 20
	recordTypeAlert            uint8 = 21
	recordTypeHandshake        uint8 = 22
	recordTypeApplicationData  uint8 = 23
)

// Handshake message types we care about (RFC 8446 Section 4).
const (
	handshakeTypeClientHello uint8 = 1
	handshakeTypeServerHello uint8 = 2
	handshakeTypeFinished    uint8 = 20
	handshakeTypeKeyUpdate   uint8 = 24
)

// TLS versions.
const (
	versionTLS12 uint16 = 0x0303
	versionTLS13 uint16 = 0x0304
)

// aeadKind selects how the per-record nonce and AAD are constructed.
type aeadKind int

const (
	frameGCM12      aeadKind = iota // RFC 5288: 4-byte fixed IV + 8-byte explicit wire nonce, AAD = seq|type|ver|len (TLS 1.2)
	frameImplicit12                 // RFC 7905: 12-byte fixed IV XOR seq, no wire nonce, AAD = seq|type|ver|len (TLS 1.2 ChaCha20)
	frame13                         // RFC 8446: 12-byte fixed IV XOR seq, AAD = record header (TLS 1.3, AES-GCM or ChaCha20)
)

// cipherSuiteInfo describes the subset of AEAD cipher suites we support.
type cipherSuiteInfo struct {
	id       uint16
	keyLen   int
	fixedIV  int // length of the fixed/implicit IV portion derived from the key schedule
	hashNew  func() hash.Hash
	tls13    bool
	isChaCha bool
	makeAEAD func(key []byte) (cipher.AEAD, error)
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func chacha(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// AEAD cipher suites we can decrypt. Anything else is skipped gracefully.
var cipherSuites = map[uint16]cipherSuiteInfo{
	// TLS 1.2 — AES-GCM
	0xC02B: {0xC02B, 16, 4, sha256.New, false, false, aesGCM},    // ECDHE_ECDSA_AES_128_GCM_SHA256
	0xC02F: {0xC02F, 16, 4, sha256.New, false, false, aesGCM},    // ECDHE_RSA_AES_128_GCM_SHA256
	0x009C: {0x009C, 16, 4, sha256.New, false, false, aesGCM},    // RSA_AES_128_GCM_SHA256
	0xC02C: {0xC02C, 32, 4, sha512.New384, false, false, aesGCM}, // ECDHE_ECDSA_AES_256_GCM_SHA384
	0xC030: {0xC030, 32, 4, sha512.New384, false, false, aesGCM}, // ECDHE_RSA_AES_256_GCM_SHA384
	0x009D: {0x009D, 32, 4, sha512.New384, false, false, aesGCM}, // RSA_AES_256_GCM_SHA384
	// TLS 1.2 — ChaCha20-Poly1305 (RFC 7905)
	0xCCA8: {0xCCA8, 32, 12, sha256.New, false, true, chacha}, // ECDHE_RSA_CHACHA20_POLY1305
	0xCCA9: {0xCCA9, 32, 12, sha256.New, false, true, chacha}, // ECDHE_ECDSA_CHACHA20_POLY1305
	// TLS 1.3
	0x1301: {0x1301, 16, 12, sha256.New, true, false, aesGCM},    // TLS_AES_128_GCM_SHA256
	0x1302: {0x1302, 32, 12, sha512.New384, true, false, aesGCM}, // TLS_AES_256_GCM_SHA384
	0x1303: {0x1303, 32, 12, sha256.New, true, true, chacha},     // TLS_CHACHA20_POLY1305_SHA256
}

func lookupCipherSuite(id uint16) (cipherSuiteInfo, bool) {
	cs, ok := cipherSuites[id]
	return cs, ok
}

// --- TLS 1.3 key schedule (RFC 8446 Section 7) ---

// expandLabel implements HKDF-Expand-Label (RFC 8446 §7.1).
func expandLabel(hashNew func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.Expand(hashNew, secret, hkdfLabel.BytesOrPanic()), out); err != nil {
		panic("tlsdecrypt: HKDF-Expand-Label failed")
	}
	return out
}

// trafficKey derives the AEAD key and IV from a traffic secret (RFC 8446 7.3).
func (cs cipherSuiteInfo) trafficKey(trafficSecret []byte) (key, iv []byte) {
	key = expandLabel(cs.hashNew, trafficSecret, "key", nil, cs.keyLen)
	iv = expandLabel(cs.hashNew, trafficSecret, "iv", nil, aeadNonceLength)
	return
}

// nextTrafficSecret advances a traffic secret on KeyUpdate (RFC 8446 7.2).
func (cs cipherSuiteInfo) nextTrafficSecret(trafficSecret []byte) []byte {
	return expandLabel(cs.hashNew, trafficSecret, "traffic upd", nil, cs.hashNew().Size())
}

// --- TLS 1.2 PRF (RFC 5246 Section 5) ---

func pHash(result, secret, seed []byte, hashNew func() hash.Hash) {
	h := hmac.New(hashNew, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		copy(result[j:], b)
		j += len(b)

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

func prf12(hashNew func() hash.Hash, secret []byte, label string, seed []byte, keyLen int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	result := make([]byte, keyLen)
	pHash(result, secret, labelAndSeed, hashNew)
	return result
}

// keysFromMasterSecret derives the TLS 1.2 AEAD write keys and IVs (RFC 5246 §6.3,
// AEAD case with no MAC key).
func keysFromMasterSecret(hashNew func() hash.Hash, masterSecret, clientRandom, serverRandom []byte, keyLen, ivLen int) (clientKey, serverKey, clientIV, serverIV []byte) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	n := 2*keyLen + 2*ivLen
	keyMaterial := prf12(hashNew, masterSecret, "key expansion", seed, n)
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]
	return
}
