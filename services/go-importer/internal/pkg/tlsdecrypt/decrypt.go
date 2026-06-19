package tlsdecrypt

// Passive TLS record decryption: given a reassembled flow's raw items and NSS
// key-log secrets, recover the plaintext as "decrypted" items. Handles AEAD
// suites (AES-GCM, ChaCha20-Poly1305) for TLS 1.2/1.3 over TCP; anything else
// (CBC, missing keys, no ClientHello in capture) is a clean no-op.

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"go-importer/internal/pkg/db"
)

// DecryptedKind is the Kind tag applied to decrypted flow items.
const DecryptedKind = "decrypted"

var errShortRecord = errors.New("tlsdecrypt: record too short for AEAD")

// Status classifies the result of attempting to decrypt a flow.
type Status int

const (
	StatusNotTLS    Status = iota // no ClientHello — not a TLS flow we handle
	StatusGiveUp                  // TLS, but terminally undecryptable: unsupported suite, no ServerHello, or keys present but no plaintext
	StatusNeedKey                 // TLS with a supported suite, but the application secret isn't available yet
	StatusDecrypted               // decrypted successfully
)

// Outcome is the result of Process. ClientRandom is set whenever a ClientHello
// was found (so callers can queue the flow for a later key); Items holds the
// decrypted plaintext when Status == StatusDecrypted.
type Outcome struct {
	Status       Status
	ClientRandom []byte
	Items        []db.FlowItem
}

// rawItems returns only the ciphertext (raw) items, so Process always works on
// the raw TLS stream regardless of what else a flow carries.
func rawItems(items []db.FlowItem) []db.FlowItem {
	out := make([]db.FlowItem, 0, len(items))
	for _, it := range items {
		if it.Kind == db.RawKind {
			out = append(out, it)
		}
	}
	return out
}

// Process inspects a flow and decrypts it if possible (keys must be non-nil).
// clientGap/serverGap are the offset of the first lost-bytes gap per direction
// (-1 if none); a direction stops decrypting at its gap, since record framing and
// AEAD sequence numbers can't survive a hole. Status tells the caller whether to
// retry later (StatusNeedKey) or give up.
func Process(keys *KeyLog, items []db.FlowItem, clientGap, serverGap int) Outcome {
	items = rawItems(items)

	clientStream := concatDirection(items, "c", clientGap)
	if !looksLikeClientHello(clientStream) {
		return Outcome{Status: StatusNotTLS}
	}
	cRecords, _ := parseRecords(clientStream)
	chType, chBody, ok := firstHandshakeMessage(cRecords)
	if !ok || chType != handshakeTypeClientHello {
		return Outcome{Status: StatusNotTLS}
	}
	clientRandom, ok := parseClientHello(chBody)
	if !ok {
		return Outcome{Status: StatusNotTLS}
	}
	out := Outcome{ClientRandom: clientRandom}

	// From here on it's a TLS flow; anything we can't handle is terminal.
	serverStream := concatDirection(items, "s", serverGap)
	sRecords, _ := parseRecords(serverStream)
	shType, shBody, ok := firstHandshakeMessage(sRecords)
	if !ok || shType != handshakeTypeServerHello {
		out.Status = StatusGiveUp // ServerHello not captured
		return out
	}
	serverRandom, suite, tls13, ok := parseServerHello(shBody)
	if !ok {
		out.Status = StatusGiveUp
		return out
	}
	cs, ok := lookupCipherSuite(suite)
	if !ok {
		out.Status = StatusGiveUp // e.g. a CBC suite
		return out
	}
	info := handshakeInfo{
		clientRandom: clientRandom,
		serverRandom: serverRandom,
		cipherSuite:  suite,
		tls13:        tls13,
	}

	clientDir, serverDir, ok := buildDirections(keys, cs, info)
	if !ok {
		out.Status = StatusNeedKey // supported suite, but no application secret yet
		return out
	}

	decrypted := decryptOrdered(clientDir, serverDir, items, clientGap, serverGap)
	if len(decrypted) == 0 {
		// We had the application secret but recovered nothing (wrong key, or a
		// handshake-only flow). Retrying won't help.
		out.Status = StatusGiveUp
		return out
	}
	out.Status = StatusDecrypted
	out.Items = decrypted
	return out
}

// decryptOrdered runs the per-direction decoders over the items in order,
// emitting decrypted plaintext items (preserving direction, order, timestamps).
func decryptOrdered(clientDir, serverDir *directionState, items []db.FlowItem, clientGap, serverGap int) []db.FlowItem {
	out := make([]db.FlowItem, 0, len(items))
	cConsumed, sConsumed := 0, 0
	for _, item := range items {
		var ds *directionState
		var gap int
		var consumed *int
		if item.From == "c" {
			ds, gap, consumed = clientDir, clientGap, &cConsumed
		} else {
			ds, gap, consumed = serverDir, serverGap, &sConsumed
		}
		if ds.dead {
			continue
		}

		data := item.Data
		if gap >= 0 {
			remaining := gap - *consumed
			if remaining <= 0 {
				ds.dead = true
				*consumed += len(item.Data)
				continue
			}
			if len(data) > remaining {
				data = data[:remaining]
				ds.dead = true
			}
		}
		*consumed += len(item.Data)

		var produced []byte
		ds.feed(data, func(pt []byte) { produced = append(produced, pt...) })
		if len(produced) > 0 {
			out = append(out, db.FlowItem{
				Kind: DecryptedKind,
				From: item.From,
				Data: produced,
				Time: item.Time,
			})
		}
	}
	return out
}

// concatDirection joins all of one direction's item data in order, capped at
// the first-gap offset (limit < 0 means no cap).
func concatDirection(items []db.FlowItem, from string, limit int) []byte {
	var out []byte
	for _, item := range items {
		if item.From != from {
			continue
		}
		out = append(out, item.Data...)
		if limit >= 0 && len(out) >= limit {
			return out[:limit]
		}
	}
	return out
}

// --- per-direction cipher state ---

type aeadState struct {
	cs     cipherSuiteInfo
	kind   aeadKind
	secret []byte // TLS 1.3 traffic secret (for KeyUpdate); nil for TLS 1.2
	aead   cipher.AEAD
	iv     []byte
	seq    uint64
}

func newAEAD12(cs cipherSuiteInfo, key, iv []byte) (*aeadState, error) {
	aead, err := cs.makeAEAD(key)
	if err != nil {
		return nil, err
	}
	kind := frameGCM12
	if cs.isChaCha {
		kind = frameImplicit12
	}
	return &aeadState{cs: cs, kind: kind, aead: aead, iv: iv}, nil
}

func newAEAD13(cs cipherSuiteInfo, secret []byte) (*aeadState, error) {
	key, iv := cs.trafficKey(secret)
	aead, err := cs.makeAEAD(key)
	if err != nil {
		return nil, err
	}
	return &aeadState{cs: cs, kind: frame13, secret: secret, aead: aead, iv: iv}, nil
}

// keyUpdate advances a TLS 1.3 traffic secret (RFC 8446 7.2) and resets seq.
func (s *aeadState) keyUpdate() {
	s.secret = s.cs.nextTrafficSecret(s.secret)
	key, iv := s.cs.trafficKey(s.secret)
	if aead, err := s.cs.makeAEAD(key); err == nil {
		s.aead = aead
		s.iv = iv
	}
	s.seq = 0
}

// open decrypts a single record at the given sequence number without mutating
// state.
func (s *aeadState) open(rec tlsRecord, seq uint64) ([]byte, error) {
	payload := rec.Payload
	switch s.kind {
	case frameGCM12:
		if len(payload) < 8+16 {
			return nil, errShortRecord
		}
		explicit := payload[:8]
		ct := payload[8:]
		nonce := make([]byte, 12)
		copy(nonce[:4], s.iv)
		copy(nonce[4:], explicit)
		aad := aad12(seq, rec.Type, rec.Version, len(ct)-16)
		return s.aead.Open(nil, nonce, ct, aad)
	case frameImplicit12:
		if len(payload) < 16 {
			return nil, errShortRecord
		}
		nonce := nonce12(s.iv, seq)
		aad := aad12(seq, rec.Type, rec.Version, len(payload)-16)
		return s.aead.Open(nil, nonce, payload, aad)
	default: // frame13
		if len(payload) < 16 {
			return nil, errShortRecord
		}
		nonce := nonce12(s.iv, seq)
		aad := recordHeader(rec.Type, rec.Version, len(payload))
		return s.aead.Open(nil, nonce, payload, aad)
	}
}

type directionState struct {
	mode13 bool

	// TLS 1.2
	activated bool       // ChangeCipherSpec seen → records are now encrypted
	state12   *aeadState // active write keys for this direction

	// TLS 1.3
	hs        *aeadState // handshake traffic secret state (nil if absent)
	ap        *aeadState // application traffic secret state (nil if absent)
	cur       *aeadState
	graduated bool
	hsBuf     []byte // inner handshake-message reassembly

	buf  []byte // leftover partial record bytes across items
	dead bool   // hit a gap or unrecoverable error
}

func (d *directionState) feed(data []byte, emit func([]byte)) {
	d.buf = append(d.buf, data...)
	records, rest := parseRecords(d.buf)
	d.buf = rest
	for _, rec := range records {
		if d.mode13 {
			d.feed13(rec, emit)
		} else {
			d.feed12(rec, emit)
		}
		if d.dead {
			return
		}
	}
}

func (d *directionState) feed12(rec tlsRecord, emit func([]byte)) {
	if !d.activated {
		if rec.Type == recordTypeChangeCipherSpec {
			d.activated = true
		}
		return // plaintext handshake / CCS — not encrypted
	}
	pt, err := d.state12.open(rec, d.state12.seq)
	if err != nil {
		// Cannot recover sequence alignment after a failure.
		d.dead = true
		return
	}
	d.state12.seq++
	if rec.Type == recordTypeApplicationData {
		emit(pt)
	}
}

func (d *directionState) feed13(rec tlsRecord, emit func([]byte)) {
	switch rec.Type {
	case recordTypeChangeCipherSpec:
		return // middlebox-compat CCS — does not consume a sequence number
	case recordTypeHandshake, recordTypeAlert:
		return // plaintext ClientHello/ServerHello or plaintext alert
	case recordTypeApplicationData:
		// fallthrough to decryption below
	default:
		return
	}

	// d.cur is guaranteed non-nil here: a direction with no secret is marked
	// dead in newDir13 and skipped by decryptOrdered before it reaches feed.
	pt, err := d.cur.open(rec, d.cur.seq)
	if err != nil {
		// Possibly we are still pointed at the handshake secret but only have
		// the application secret (or vice-versa); try graduating once.
		if d.cur == d.hs && d.ap != nil && !d.graduated {
			d.cur = d.ap
			d.graduated = true
			pt, err = d.cur.open(rec, d.cur.seq)
		}
		if err != nil {
			return // skip this record without consuming a sequence number
		}
	}
	d.cur.seq++

	inner, innerType := stripPadding13(pt)
	switch innerType {
	case recordTypeApplicationData:
		emit(inner)
	case recordTypeHandshake:
		d.processInnerHandshake13(inner)
	}
}

// processInnerHandshake13 watches the inner handshake stream for Finished
// (graduate handshake → application secret) and KeyUpdate (ratchet the secret).
func (d *directionState) processInnerHandshake13(inner []byte) {
	d.hsBuf = append(d.hsBuf, inner...)
	for len(d.hsBuf) >= 4 {
		msgType := d.hsBuf[0]
		msgLen := int(d.hsBuf[1])<<16 | int(d.hsBuf[2])<<8 | int(d.hsBuf[3])
		if len(d.hsBuf) < 4+msgLen {
			break
		}
		d.hsBuf = d.hsBuf[4+msgLen:]
		switch msgType {
		case handshakeTypeFinished:
			if d.cur == d.hs && d.ap != nil && !d.graduated {
				d.cur = d.ap
				d.cur.seq = 0
				d.graduated = true
			}
		case handshakeTypeKeyUpdate:
			if d.cur == d.ap {
				d.ap.keyUpdate()
			}
		}
	}
}

func buildDirections(keys *KeyLog, cs cipherSuiteInfo, info handshakeInfo) (client, server *directionState, ok bool) {
	if info.tls13 {
		chs, _ := keys.Lookup(info.clientRandom, "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
		shs, _ := keys.Lookup(info.clientRandom, "SERVER_HANDSHAKE_TRAFFIC_SECRET")
		cap0, _ := keys.Lookup(info.clientRandom, "CLIENT_TRAFFIC_SECRET_0")
		sap0, _ := keys.Lookup(info.clientRandom, "SERVER_TRAFFIC_SECRET_0")
		// Need at least one application traffic secret; handshake-only secrets
		// aren't enough but shouldn't make us give up (app secret may not be logged yet).
		if cap0 == nil && sap0 == nil {
			return nil, nil, false
		}
		client = newDir13(cs, chs, cap0)
		server = newDir13(cs, shs, sap0)
		return client, server, true
	}

	master, found := keys.Lookup(info.clientRandom, "CLIENT_RANDOM")
	if !found {
		return nil, nil, false
	}
	clientKey, serverKey, clientIV, serverIV := keysFromMasterSecret(
		cs.hashNew, master, info.clientRandom, info.serverRandom, cs.keyLen, cs.fixedIV)
	clientAEAD, err1 := newAEAD12(cs, clientKey, clientIV)
	serverAEAD, err2 := newAEAD12(cs, serverKey, serverIV)
	if err1 != nil || err2 != nil {
		return nil, nil, false
	}
	return &directionState{state12: clientAEAD}, &directionState{state12: serverAEAD}, true
}

func newDir13(cs cipherSuiteInfo, handshakeSecret, appSecret []byte) *directionState {
	d := &directionState{mode13: true}
	if handshakeSecret != nil {
		if st, err := newAEAD13(cs, handshakeSecret); err == nil {
			d.hs = st
		}
	}
	if appSecret != nil {
		if st, err := newAEAD13(cs, appSecret); err == nil {
			d.ap = st
		}
	}
	if d.hs != nil {
		d.cur = d.hs
	} else {
		d.cur = d.ap
		d.graduated = true
	}
	// No secret for this direction: mark it terminal so decryptOrdered skips it.
	if d.cur == nil {
		d.dead = true
	}
	return d
}

// stripPadding13 removes TLS 1.3 trailing zero padding and returns the inner
// content and its true content type (RFC 8446 5.2).
func stripPadding13(pt []byte) (inner []byte, innerType uint8) {
	i := len(pt) - 1
	for i >= 0 && pt[i] == 0 {
		i--
	}
	if i < 0 {
		return nil, 0
	}
	return pt[:i], pt[i]
}

// --- nonce / AAD helpers ---

func nonce12(iv []byte, seq uint64) []byte {
	n := make([]byte, len(iv))
	copy(n, iv)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	for i := 0; i < 8; i++ {
		n[len(n)-8+i] ^= s[i]
	}
	return n
}

func aad12(seq uint64, typ uint8, version uint16, length int) []byte {
	b := make([]byte, 13)
	binary.BigEndian.PutUint64(b[0:8], seq)
	b[8] = typ
	b[9] = byte(version >> 8)
	b[10] = byte(version)
	b[11] = byte(length >> 8)
	b[12] = byte(length)
	return b
}

func recordHeader(typ uint8, version uint16, length int) []byte {
	return []byte{typ, byte(version >> 8), byte(version), byte(length >> 8), byte(length)}
}
