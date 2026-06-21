package mine

import (
	"bytes"
	"regexp"
)

// SlotType classifies a variable slot of a template by what its values are
// across the cluster's members.
type SlotType int

const (
	SlotUnknown SlotType = iota // varies, unclassified
	SlotConst                   // a single value (not actually variable)
	SlotFlag                    // our flag, loot to strip
	SlotFlagID                  // a flagId, re-fetched per target
	SlotRandom                  // high-entropy nonce, regenerate
)

func (s SlotType) String() string {
	switch s {
	case SlotConst:
		return "const"
	case SlotFlag:
		return "flag"
	case SlotFlagID:
		return "flagid"
	case SlotRandom:
		return "random"
	default:
		return "unknown"
	}
}

// extractSlotValues returns member's bytes in each variable slot of the
// template, located by the constant anchors in order. Returns nil if an anchor
// is missing (member does not fit the template).
func extractSlotValues(member []byte, segs []Segment) [][]byte {
	var values [][]byte
	pos := 0
	pendingVar := false
	for _, s := range segs {
		if s.Var {
			pendingVar = true
			continue
		}
		idx := bytes.Index(member[pos:], s.Const)
		if idx < 0 {
			return nil
		}
		if pendingVar {
			values = append(values, member[pos:pos+idx])
			pendingVar = false
		}
		pos += idx + len(s.Const)
	}
	if pendingVar {
		values = append(values, member[pos:])
	}
	return values
}

// classifySlot types one slot from its per-member values. Flag and flagId
// (exact, against the live set) are checked before the generic high-entropy
// (random) test, since those are also high-entropy.
func classifySlot(values [][]byte, flagRe *regexp.Regexp, flagIDs map[string]bool) SlotType {
	if len(values) == 0 {
		return SlotUnknown
	}
	distinct := map[string]struct{}{}
	allFlag, allFlagID, allRandom := true, true, true
	for _, v := range values {
		tv := bytes.TrimSpace(v)
		distinct[string(tv)] = struct{}{}
		if flagRe == nil || !flagRe.Match(tv) {
			allFlag = false
		}
		if !flagIDs[string(tv)] {
			allFlagID = false
		}
		if !IsHighEntropyToken(tv) {
			allRandom = false
		}
	}
	if len(distinct) == 1 {
		return SlotConst
	}
	switch {
	case allFlag:
		return SlotFlag
	case allFlagID:
		return SlotFlagID
	case allRandom:
		return SlotRandom
	default:
		return SlotUnknown
	}
}

// Template is a synthesized, typed request template for a cluster: the aligned
// segments plus a type for each variable slot, in order.
type Template struct {
	Segments []Segment
	Slots    []SlotType
}

func countVarSegments(segs []Segment) int {
	n := 0
	for _, s := range segs {
		if s.Var {
			n++
		}
	}
	return n
}

// synthesize builds a typed template from a cluster's member requests (unmasked
// canonical forms). Returns nil with fewer than coreQuorum members or no shape.
func synthesize(members [][]byte, flagRe *regexp.Regexp, flagIDs map[string]bool) *Template {
	if len(members) < coreQuorum {
		return nil
	}
	segs := Align(members)
	nSlots := countVarSegments(segs)

	perSlot := make([][][]byte, nSlots)
	for _, m := range members {
		vals := extractSlotValues(m, segs)
		if len(vals) != nSlots {
			continue
		}
		for i, v := range vals {
			perSlot[i] = append(perSlot[i], v)
		}
	}

	slots := make([]SlotType, nSlots)
	for i := range slots {
		slots[i] = classifySlot(perSlot[i], flagRe, flagIDs)
	}
	return &Template{Segments: segs, Slots: slots}
}
