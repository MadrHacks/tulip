package db

import (
	"bytes"
	"testing"
)

func TestGroupTurnsMergesConsecutiveSameDirection(t *testing.T) {
	// A client turn split across two packets, a multi-packet server reply, then a
	// second client turn: consecutive same-direction chunks collapse into one turn.
	chunks := []rawChunk{
		{fromClient: true, data: []byte("sign")},
		{fromClient: true, data: []byte("up\n")},
		{fromClient: false, data: []byte("User")},
		{fromClient: false, data: []byte("name: ")},
		{fromClient: true, data: []byte("readflag\n")},
		{fromClient: false, data: []byte("FLAG{x}")},
	}
	turns := groupTurns(chunks)

	want := []Turn{
		{FromClient: true, Data: []byte("signup\n")},
		{FromClient: false, Data: []byte("Username: ")},
		{FromClient: true, Data: []byte("readflag\n")},
		{FromClient: false, Data: []byte("FLAG{x}")},
	}
	if len(turns) != len(want) {
		t.Fatalf("got %d turns, want %d: %+v", len(turns), len(want), turns)
	}
	for i, w := range want {
		if turns[i].FromClient != w.FromClient || !bytes.Equal(turns[i].Data, w.Data) {
			t.Errorf("turn %d = {client:%v %q}, want {client:%v %q}",
				i, turns[i].FromClient, turns[i].Data, w.FromClient, w.Data)
		}
	}
}

func TestGroupTurnsEmpty(t *testing.T) {
	if turns := groupTurns(nil); turns != nil {
		t.Errorf("groupTurns(nil) = %+v, want nil", turns)
	}
}

func TestGroupTurnsDoesNotAliasChunkBuffers(t *testing.T) {
	// pgx reuses row scan buffers; a turn must own its bytes. Mutating a chunk's
	// backing array after grouping must not change the turn.
	buf := []byte("abc")
	turns := groupTurns([]rawChunk{{fromClient: true, data: buf}})
	buf[0] = 'Z'
	if !bytes.Equal(turns[0].Data, []byte("abc")) {
		t.Errorf("turn aliased the chunk buffer: got %q", turns[0].Data)
	}
}
