package mine

import (
	"bytes"
	"regexp"
	"strconv"
)

// Request-unit shape pipeline — stage 1: split ONE flow into REQUEST UNITS.
//
// This is a faithful Go port of the validated Python prototype
// (ad-captures/preserved/pipeline/stage1_segment.py). It is the #1 lever:
// clustering whole pipelined keep-alive flows shatters the shape space, so we
// first cut a flow's client byte-stream into individual request units and pair
// each with its response.
//
// Two protocol families:
//
//	HTTP: LENGTH-AWARE split. We do NOT split on a `^METHOD ... HTTP/1.x` line
//	  anchor — request bodies are glued directly to the next request line with
//	  no separator, so an anchor split silently drops requests. Instead we parse
//	  headers up to CRLFCRLF, read Content-Length bytes of body (or walk a
//	  Transfer-Encoding: chunked body, or run to end-of-stream for a response
//	  with Connection: close), then repeat. Request i pairs with response i by
//	  order.
//
//	LINE / menu (skypedia 1337): the client stream is a sequence of menu ops — a
//	  structural opcode digit line (1/2/3/4/5/6/99) followed by its argument
//	  lines. We split on those opcode anchors. Per-op response pairing is not
//	  recoverable from a concatenated export, so line units carry a nil response
//	  and fall back to FLOW-LEVEL response features (see respfeatures.go).

// flagShapeRe is the CC2026 game flag token: 31 uppercase-alnum chars + '='.
// Defined here (rather than reusing the engine's config-driven regex) so the
// shape pipeline reproduces the prototype's constant exactly.
var flagShapeRe = regexp.MustCompile(`[A-Z0-9]{31}=`)

// linePorts are ports whose wire protocol is the skypedia line/menu protocol
// (not HTTP). Mirrors common.LINE_PORTS in the prototype.
var linePorts = map[int]bool{1337: true}

// lineOpcodes anchor a new request-unit in the line protocol. Mirrors
// common.LINE_OPCODES.
var lineOpcodes = map[string]bool{"1": true, "2": true, "3": true, "4": true, "5": true, "6": true, "99": true}

// RequestUnit is one request within a flow, with its paired response bytes.
// Response is nil for the line protocol (per-op response not recoverable) or
// when a flow has more requests than responses.
type RequestUnit struct {
	Svc      string // service shard the unit belongs to
	Proto    string // "http" | "line"
	Index    int    // position within the flow
	Client   []byte // the request unit's client->server bytes
	Response []byte // the paired response, or nil
}

// SegmentedFlow is a flow cut into ordered request units, retaining the whole
// server stream as a flow-level fallback for the line protocol.
type SegmentedFlow struct {
	ID      string
	Svc     string
	Port    int
	FlagOut bool
	FlagIn  bool
	Proto   string // "http" | "line"
	Server  []byte // whole server stream (flow-level fallback)
	Units   []RequestUnit
}

var (
	reCLen      = regexp.MustCompile(`(?i)\r\ncontent-length:[ \t]*(\d+)`)
	reChunked   = regexp.MustCompile(`(?i)\r\ntransfer-encoding:[ \t]*chunked`)
	reConnClose = regexp.MustCompile(`(?i)\r\nconnection:[ \t]*close`)
)

// SegmentFlow splits a flow's client/server byte streams into ordered request
// units. proto is chosen by port: a line port yields opcode-anchored line units
// (nil responses), otherwise HTTP length-aware units paired by order.
func SegmentFlow(id, svc string, port int, flagOut, flagIn bool, client, server []byte) SegmentedFlow {
	fl := SegmentedFlow{ID: id, Svc: svc, Port: port, FlagOut: flagOut, FlagIn: flagIn, Server: server}
	if linePorts[port] {
		fl.Proto = "line"
		for i, ob := range splitLineOps(client) {
			fl.Units = append(fl.Units, RequestUnit{Svc: svc, Proto: "line", Index: i, Client: ob})
		}
		return fl
	}
	fl.Proto = "http"
	reqs := splitHTTPRequests(client)
	resps := splitHTTPResponses(server)
	for i, rq := range reqs {
		var resp []byte
		if i < len(resps) {
			resp = resps[i]
		}
		fl.Units = append(fl.Units, RequestUnit{Svc: svc, Proto: "http", Index: i, Client: rq, Response: resp})
	}
	return fl
}

// splitHTTPRequests cuts a client stream into request units by header+body
// length: Content-Length, else chunked, else no body.
func splitHTTPRequests(data []byte) [][]byte {
	var out [][]byte
	i, n := 0, len(data)
	for i < n {
		he := bytes.Index(data[i:], crlfCRLF)
		if he == -1 {
			if tail := data[i:]; len(bytes.TrimSpace(tail)) > 0 {
				out = append(out, tail)
			}
			break
		}
		he += i // absolute index of the CRLFCRLF
		head := headWithLeadingCRLF(data, i, he)
		bodyStart := he + 4
		end := bodyStart
		if m := reCLen.FindSubmatch(head); m != nil {
			cl, _ := strconv.Atoi(string(m[1]))
			end = bodyStart + cl
		} else if reChunked.Match(head) {
			end = consumeChunked(data, bodyStart, n)
		}
		if end > n {
			end = n
		}
		out = append(out, data[i:end])
		i = end
	}
	return nonEmpty(out)
}

// splitHTTPResponses cuts a server stream into response units. Adds
// Connection: close handling (body runs to end of stream) on top of the request
// rules.
func splitHTTPResponses(data []byte) [][]byte {
	var out [][]byte
	i, n := 0, len(data)
	for i < n {
		he := bytes.Index(data[i:], crlfCRLF)
		if he == -1 {
			if tail := data[i:]; len(bytes.TrimSpace(tail)) > 0 {
				out = append(out, tail)
			}
			break
		}
		he += i
		head := headWithLeadingCRLF(data, i, he)
		bodyStart := he + 4
		end := bodyStart
		if m := reCLen.FindSubmatch(head); m != nil {
			cl, _ := strconv.Atoi(string(m[1]))
			end = bodyStart + cl
		} else if reChunked.Match(head) {
			end = consumeChunked(data, bodyStart, n)
		} else if reConnClose.Match(head) {
			end = n
		}
		if end > n {
			end = n
		}
		out = append(out, data[i:end])
		i = end
	}
	return nonEmpty(out)
}

var crlfCRLF = []byte("\r\n\r\n")

// headWithLeadingCRLF returns the header slice data[start:end] with a leading
// "\r\n" prepended, so the header-matching regexes' `\r\n` anchor matches the
// very first header line (mirrors the prototype's `b"\r\n" + head`).
func headWithLeadingCRLF(data []byte, start, end int) []byte {
	head := make([]byte, 0, end-start+2)
	head = append(head, '\r', '\n')
	head = append(head, data[start:end]...)
	return head
}

// consumeChunked walks Transfer-Encoding: chunked body from j to the "0\r\n"
// terminator, returning the index just past it.
func consumeChunked(data []byte, j, n int) int {
	for j < n {
		crlf := bytes.Index(data[j:], []byte("\r\n"))
		if crlf == -1 {
			return n
		}
		crlf += j
		sizeField := data[j:crlf]
		if semi := bytes.IndexByte(sizeField, ';'); semi != -1 {
			sizeField = sizeField[:semi]
		}
		sz, err := strconv.ParseInt(string(bytes.TrimSpace(sizeField)), 16, 64)
		if err != nil {
			return n
		}
		if sz == 0 {
			end := bytes.Index(data[crlf+2:], []byte("\r\n"))
			if end == -1 {
				return n
			}
			return crlf + 2 + end + 2
		}
		j = crlf + 2 + int(sz) + 2
	}
	return n
}

// splitLineOps splits a client stream into menu ops: an opcode line
// (1/2/3/4/5/6/99) starts a new unit; following non-opcode lines are its args.
func splitLineOps(data []byte) [][]byte {
	lines := bytes.Split(data, []byte("\n"))
	var ops [][]byte
	var cur [][]byte
	for _, ln := range lines {
		tok := string(bytes.TrimSpace(ln))
		if lineOpcodes[tok] {
			if len(cur) > 0 {
				ops = append(ops, bytes.Join(cur, []byte("\n")))
			}
			cur = [][]byte{ln}
		} else {
			if len(cur) > 0 || tok != "" {
				cur = append(cur, ln)
			}
		}
	}
	if len(cur) > 0 {
		ops = append(ops, bytes.Join(cur, []byte("\n")))
	}
	return nonEmpty(ops)
}

// nonEmpty drops units that are empty after trimming whitespace.
func nonEmpty(units [][]byte) [][]byte {
	out := units[:0:len(units)]
	for _, u := range units {
		if len(bytes.TrimSpace(u)) > 0 {
			out = append(out, u)
		}
	}
	return out
}
