package mine

// Held-out fidelity EXPORT harness (validation only). Reads flows.json (testable
// shapes grouped by the reference skeleton) and, for each shape, runs the REAL
// synthesis path — analyseShape + emitPlan — over the full group (for the gate
// verdict) and over each leave-one-out N-1 build (for the replay test), writing
// plans.json for the Python interactive_replay harness to execute against the
// held-out server bytes. Skipped unless REPRO_HELDOUT_IN/OUT are set, so the
// normal `go test ./...` run stays green.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"sort"
	"testing"

	"go-importer/internal/pkg/db"
)

const maxHeldOutFolds = 15 // matches run_all.py MAX_FOLDS

type shapeIn struct {
	Dataset string        `json:"dataset"`
	Service string        `json:"service"`
	Port    int           `json:"port"`
	Sig     string        `json:"sig"`
	Flows   [][][2]string `json:"flows"` // [flow][turn] = [dir("C"|"S"), b64]
}

type flowsIn struct {
	Shapes []shapeIn `json:"shapes"`
}

type slotSummary struct {
	TI       int    `json:"ti"`
	VK       int    `json:"vk"`
	Kind     string `json:"kind"`
	External bool   `json:"external"`
	Sla      bool   `json:"sla"`
}

type foldOut struct {
	HeldoutIndex int             `json:"heldout_index"`
	Heldout      [][2]string     `json:"heldout"`
	Plan         json.RawMessage `json:"plan"`
	Required     []int           `json:"required"`
	BuildGated   bool            `json:"build_gated"`
	BuildReason  string          `json:"build_reason"`
}

type shapeOut struct {
	Dataset      string        `json:"dataset"`
	Service      string        `json:"service"`
	Sig          string        `json:"sig"`
	Port         int           `json:"port"`
	N            int           `json:"n"`
	FullOK       bool          `json:"full_ok"`
	FullGate     []string      `json:"full_gate"`
	FullRequired []int         `json:"full_required"`
	FullSlots    []slotSummary `json:"full_slots"`
	Folds        []foldOut     `json:"folds"`
}

func decodeFlow(inst [][2]string) []db.Turn {
	turns := make([]db.Turn, 0, len(inst))
	for _, tv := range inst {
		data, err := base64.StdEncoding.DecodeString(tv[1])
		if err != nil {
			panic(err)
		}
		turns = append(turns, db.Turn{FromClient: tv[0] == "C", Data: data})
	}
	return turns
}

// summarizeRequiredSlots reports the classification of every slot on a required
// turn — enough for the Python side to reproduce run_all.py's attack-class
// (EXFIL vs self-read vs SLA) tally.
func summarizeRequiredSlots(prog *reproProgram) []slotSummary {
	if !prog.ok {
		return nil
	}
	req := map[int]bool{}
	for _, t := range prog.required {
		req[t] = true
	}
	var out []slotSummary
	for _, sv := range prog.vslotIndex {
		if !req[sv[0]] {
			continue
		}
		c := prog.classes[sv]
		out = append(out, slotSummary{TI: sv[0], VK: sv[1], Kind: c.kind,
			External: c.external, Sla: c.slaSelfMirror})
	}
	return out
}

func fullGateReasons(prog *reproProgram, service string, port int) (bool, []string) {
	plan := emitPlan(prog, service, port)
	if !prog.ok {
		return false, []string{plan.Reason}
	}
	return true, prog.gate
}

func TestHeldOutExport(t *testing.T) {
	inPath := os.Getenv("REPRO_HELDOUT_IN")
	outPath := os.Getenv("REPRO_HELDOUT_OUT")
	if inPath == "" || outPath == "" {
		t.Skip("set REPRO_HELDOUT_IN and REPRO_HELDOUT_OUT to run the held-out export")
	}
	raw, err := os.ReadFile(inPath)
	if err != nil {
		t.Fatalf("read %s: %v", inPath, err)
	}
	var in flowsIn
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("unmarshal flows: %v", err)
	}

	var results []shapeOut
	for _, sh := range in.Shapes {
		flows := make([][]db.Turn, len(sh.Flows))
		for i, inst := range sh.Flows {
			flows[i] = decodeFlow(inst)
		}
		n := len(flows)

		// FULL: authoritative gate/classification verdict over the whole group.
		fullProg := analyseShape(flows, sh.Service, sh.Port, avFlagRe)
		fullOK, fullGate := fullGateReasons(fullProg, sh.Service, sh.Port)
		so := shapeOut{
			Dataset: sh.Dataset, Service: sh.Service, Sig: sh.Sig, Port: sh.Port, N: n,
			FullOK: fullOK, FullGate: fullGate,
		}
		if fullOK {
			so.FullRequired = fullProg.required
			so.FullSlots = summarizeRequiredSlots(fullProg)
		}

		// LOO folds: synthesize each N-1 build plan for the Python replay.
		folds := n
		if folds > maxHeldOutFolds {
			folds = maxHeldOutFolds
		}
		for h := 0; h < folds; h++ {
			build := make([][]db.Turn, 0, n-1)
			for i := 0; i < n; i++ {
				if i != h {
					build = append(build, flows[i])
				}
			}
			prog := analyseShape(build, sh.Service, sh.Port, avFlagRe)
			plan := emitPlan(prog, sh.Service, sh.Port)
			planJSON, err := json.Marshal(plan)
			if err != nil {
				t.Fatalf("marshal plan: %v", err)
			}
			req := []int{}
			if prog.ok {
				req = append(req, prog.required...)
				sort.Ints(req)
			}
			so.Folds = append(so.Folds, foldOut{
				HeldoutIndex: h,
				Heldout:      sh.Flows[h],
				Plan:         planJSON,
				Required:     req,
				BuildGated:   plan.Unreproducible,
				BuildReason:  plan.Reason,
			})
		}
		results = append(results, so)
	}

	outRaw, err := json.Marshal(struct {
		Shapes []shapeOut `json:"shapes"`
	}{results})
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	if err := os.WriteFile(outPath, outRaw, 0o644); err != nil {
		t.Fatalf("write %s: %v", outPath, err)
	}
	t.Logf("wrote %d shapes -> %s", len(results), outPath)
}
