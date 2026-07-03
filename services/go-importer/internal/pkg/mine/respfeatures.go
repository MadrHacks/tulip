package mine

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
)

// Request-unit shape pipeline — stage 3: per-request-unit response features.
// Faithful port of stage3_response_features.py.
//
// Features are OBSERVABLE SIGNALS only — no attack verdict lives here.
// flag_present is the load-bearing signal: stage 5 splits on it to peel a
// "GET /user WITH FLAG LEAK" shape off a byte-identical benign browse shape.
// It is a SIGNAL (this response leaked a flag), not a verdict — the checker
// also leaks flags.

var (
	reStatus  = regexp.MustCompile(`^HTTP/1\.[01] (\d{3})`)
	reB64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)
)

// RespFeatures is one request unit's response signal vector.
type RespFeatures struct {
	HTTPStatus          int    // 0 = none (line proto / unparsed)
	ContentType         string // before ';', lowercased; "" = none; "line" = line-proto fallback
	ContentLengthBucket int    // floor(log2(bodyLen + 1))
	FlagPresent         bool   // flag regex present raw OR after recursive base64/gzip decode
}

// gunzip attempts to inflate b as gzip, then zlib, then raw deflate, returning
// nil if none succeed. Mirrors the prototype's gzip/zlib decode attempts.
func gunzip(b []byte) []byte {
	if zr, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
		if out, err := io.ReadAll(zr); err == nil {
			return out
		}
	}
	if zr, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
		if out, err := io.ReadAll(zr); err == nil {
			return out
		}
	}
	fr := flate.NewReader(bytes.NewReader(b))
	if out, err := io.ReadAll(fr); err == nil && len(out) > 0 {
		return out
	}
	return nil
}

// ScanFlag reports whether the flag appears in data: raw, then after gunzip,
// then after decoding the largest base64-looking blobs and recursing (bounded
// by depth). This surfaces flags hidden inside gzip'd JSON and base64-JPEGs that
// a raw matcher misses.
func ScanFlag(data []byte, depth int) bool {
	if len(data) == 0 {
		return false
	}
	if flagShapeRe.Match(data) {
		return true
	}
	if depth <= 0 {
		return false
	}
	if g := gunzip(data); g != nil && ScanFlag(g, depth-1) {
		return true
	}
	blobs := reB64Blob.FindAll(data, -1)
	sort.SliceStable(blobs, func(i, j int) bool { return len(blobs[i]) > len(blobs[j]) })
	if len(blobs) > 4 {
		blobs = blobs[:4]
	}
	for _, blob := range blobs {
		dec := b64decodeLenient(blob)
		if dec != nil && ScanFlag(dec, depth-1) {
			return true
		}
	}
	return false
}

// b64decodeLenient decodes a standard-alphabet base64 blob, tolerating missing
// or excess '=' padding (matching Python's lenient base64.b64decode).
func b64decodeLenient(blob []byte) []byte {
	s := bytes.TrimRight(blob, "=")
	if len(s)%4 == 1 {
		return nil
	}
	dec, err := base64.RawStdEncoding.DecodeString(string(s))
	if err != nil {
		return nil
	}
	return dec
}

func clenBucket(n int) int {
	return int(math.Floor(math.Log2(float64(n + 1))))
}

// ResponseFeatures extracts the signal vector for one request unit's paired
// response. A nil/empty response yields the neutral zero vector.
func ResponseFeatures(response []byte) RespFeatures {
	if len(response) == 0 {
		return RespFeatures{}
	}
	f := RespFeatures{}
	if m := reStatus.FindSubmatch(response); m != nil {
		f.HTTPStatus, _ = strconv.Atoi(string(m[1]))
	}
	if m := reCThdr.FindSubmatch(response); m != nil {
		f.ContentType = trimLowerCT(m[1])
	}
	body := response
	if he := bytes.Index(response, crlfCRLF); he != -1 {
		body = response[he+4:]
	}
	f.ContentLengthBucket = clenBucket(len(body))
	f.FlagPresent = ScanFlag(response, 2)
	return f
}

// FlowLevelFeatures is the fallback for the line protocol, where per-op
// responses can't be recovered: features over the whole server stream.
func FlowLevelFeatures(server []byte) RespFeatures {
	return RespFeatures{
		HTTPStatus:          0,
		ContentType:         "line",
		ContentLengthBucket: clenBucket(len(server)),
		FlagPresent:         ScanFlag(server, 2),
	}
}

// trimLowerCT lowercases and trims a content-type capture (already excludes ';'
// via the header regex).
func trimLowerCT(b []byte) string {
	return string(bytes.ToLower(bytes.TrimSpace(b)))
}
