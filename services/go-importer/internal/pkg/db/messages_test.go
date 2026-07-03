package db

import (
	"bytes"
	"testing"
)

func TestOrderedMessagesPreservesInterleaving(t *testing.T) {
	// The offline prototype concatenated all client then all server bytes and
	// lost the alternation; ordered messages keep the real back-and-forth so a
	// segmenter can pair each request with the response that followed it.
	chunks := []dirChunk{
		{fromClient: true, kind: "raw", data: []byte("op1\n")},
		{fromClient: false, kind: "raw", data: []byte("resp1\n")},
		{fromClient: true, kind: "raw", data: []byte("op2\n")},
		{fromClient: false, kind: "raw", data: []byte("resp2\n")},
	}
	msgs := orderedMessages(chunks)
	want := []FlowMessage{
		{FromClient: true, Data: []byte("op1\n")},
		{FromClient: false, Data: []byte("resp1\n")},
		{FromClient: true, Data: []byte("op2\n")},
		{FromClient: false, Data: []byte("resp2\n")},
	}
	if len(msgs) != len(want) {
		t.Fatalf("got %d messages, want %d: %+v", len(msgs), len(want), msgs)
	}
	for i, w := range want {
		if msgs[i].FromClient != w.FromClient || !bytes.Equal(msgs[i].Data, w.Data) {
			t.Errorf("msg %d = {client:%v %q}, want {client:%v %q}",
				i, msgs[i].FromClient, msgs[i].Data, w.FromClient, w.Data)
		}
	}
}

func TestOrderedMessagesPerDirectionTopmost(t *testing.T) {
	// Client only exists raw (ciphertext undecodable), server was TLS-decrypted:
	// each direction keeps its own deepest layer instead of one global choice
	// dropping a whole side.
	chunks := []dirChunk{
		{fromClient: true, kind: "raw", data: []byte("CLIENT")},
		{fromClient: false, kind: "raw", data: []byte("CIPHER")},
		{fromClient: false, kind: "decrypted", data: []byte("PLAIN")},
	}
	msgs := orderedMessages(chunks)
	// Expect the raw client message, then only the decrypted server message.
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2: %+v", len(msgs), msgs)
	}
	if !msgs[0].FromClient || !bytes.Equal(msgs[0].Data, []byte("CLIENT")) {
		t.Errorf("msg0 = %+v, want raw client CLIENT", msgs[0])
	}
	if msgs[1].FromClient || !bytes.Equal(msgs[1].Data, []byte("PLAIN")) || msgs[1].Kind != "decrypted" {
		t.Errorf("msg1 = %+v, want decrypted server PLAIN", msgs[1])
	}
}

func TestOrderedMessagesDoesNotAliasBuffers(t *testing.T) {
	// pgx reuses row scan buffers; a message must own its bytes.
	buf := []byte("abc")
	msgs := orderedMessages([]dirChunk{{fromClient: true, kind: "raw", data: buf}})
	buf[0] = 'Z'
	if !bytes.Equal(msgs[0].Data, []byte("abc")) {
		t.Errorf("message aliased the chunk buffer: got %q", msgs[0].Data)
	}
}

func TestOrderedMessagesEmpty(t *testing.T) {
	if msgs := orderedMessages(nil); msgs != nil {
		t.Errorf("orderedMessages(nil) = %+v, want nil", msgs)
	}
}
