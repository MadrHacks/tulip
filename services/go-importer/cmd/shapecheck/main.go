// Command shapecheck runs the request-unit shape pipeline (mine.SegmentFlow ->
// NormalizeUnit -> ResponseFeatures -> Drain -> shapes/splits/sessions) over the
// preserved cc2026 dataset and prints parity metrics against the Python
// prototype: total shapes, singleton rate, and how many shapes cover 90% of the
// flag-leaving request units.
//
// Usage:
//
//	go run ./cmd/shapecheck [path/to/today-flows-rich.jsonl]
//
// Defaults to the preserved dataset path.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"go-importer/internal/pkg/mine"
)

const defaultData = "/home/rob/MadrHacks/ad-captures/preserved/today-flows-rich.jsonl"

// portSvc and services mirror the prototype harness (harness.py).
var portSvc = map[int]string{1337: "skypedia", 8081: "skypedia", 8080: "boomthrow", 6006: "dutyfree", 3000: "controltower"}
var services = []string{"skypedia", "boomthrow", "dutyfree", "controltower"}

type rawRec struct {
	ID        string `json:"id"`
	Port      int    `json:"port"`
	FlagOut   bool   `json:"flag_out"`
	FlagIn    bool   `json:"flag_in"`
	ClientB64 string `json:"client_b64"`
	ServerB64 string `json:"server_b64"`
}

type unitRow struct {
	svc         string
	flowIdx     int
	skeleton    string
	ua          string
	feats       mine.RespFeatures
	flagPresent bool
	isExfil     bool
	shapeID     int // global per-request shape id (stage 4a)
	splitID     int // global split-shape id (stage 5)
}

type flowRow struct {
	svc      string
	flagOut  bool
	proto    string
	unitRows []int // indices into units
}

func main() {
	path := defaultData
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open dataset:", err)
		os.Exit(1)
	}
	defer f.Close()

	t0 := time.Now()

	var flows []flowRow
	var units []unitRow
	svcUnits := map[string][]int{}

	// Cross-check: the streaming ShapeStore should derive the same number of
	// per-request shapes as the pure per-service Drain pass below. It is fed the
	// same segmented units + response features, one flow at a time.
	store := mine.NewShapeStore(0)

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r rawRec
		if err := json.Unmarshal(line, &r); err != nil {
			fmt.Fprintln(os.Stderr, "parse:", err)
			os.Exit(1)
		}
		svc, ok := portSvc[r.Port]
		if !ok {
			continue
		}
		client, _ := base64.StdEncoding.DecodeString(r.ClientB64)
		server, _ := base64.StdEncoding.DecodeString(r.ServerB64)
		fl := mine.SegmentFlow(r.ID, svc, r.Port, r.FlagOut, r.FlagIn, client, server)

		fidx := len(flows)
		fr := flowRow{svc: svc, flagOut: r.FlagOut, proto: fl.Proto}
		flFeats := make([]mine.RespFeatures, 0, len(fl.Units))
		for _, u := range fl.Units {
			sk, ua := mine.NormalizeUnit(u)
			var feats mine.RespFeatures
			var isExfil bool
			if u.Proto == "http" {
				feats = mine.ResponseFeatures(u.Response)
				isExfil = len(u.Response) > 0 && mine.ScanFlag(u.Response, 0)
			} else {
				feats = mine.FlowLevelFeatures(fl.Server)
				isExfil = fl.FlagOut // line proto: cannot localize per op
			}
			flFeats = append(flFeats, feats)
			uidx := len(units)
			units = append(units, unitRow{
				svc: svc, flowIdx: fidx, skeleton: sk, ua: ua,
				feats: feats, flagPresent: feats.FlagPresent, isExfil: isExfil,
				shapeID: -1, splitID: -1,
			})
			fr.unitRows = append(fr.unitRows, uidx)
			svcUnits[svc] = append(svcUnits[svc], uidx)
		}
		store.Observe(svc, fl.Units, flFeats, r.FlagIn, int64(fidx))
		flows = append(flows, fr)
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
		os.Exit(1)
	}

	// stage 4a: per-service Drain -> global shape ids (shapes never cross svc).
	globalShape := map[string]int{}
	shapeTemplate := map[int]string{}
	for _, svc := range services {
		g := mine.NewShapeGrouper()
		local := map[int]int{} // drain id -> global id
		for _, uidx := range svcUnits[svc] {
			cid := g.Add(units[uidx].skeleton)
			key := svc + "#" + itoa(cid)
			gid, ok := globalShape[key]
			if !ok {
				gid = len(globalShape)
				globalShape[key] = gid
			}
			local[cid] = gid
			units[uidx].shapeID = gid
		}
		for cid, tmpl := range g.Templates() {
			if gid, ok := local[cid]; ok {
				shapeTemplate[gid] = tmpl
			}
		}
	}

	// stage 5: split by response feature -> global split ids.
	globalSplit := map[mine.SplitKey]int{}
	for i := range units {
		key := mine.MakeSplitKey(units[i].shapeID, units[i].feats)
		sid, ok := globalSplit[key]
		if !ok {
			sid = len(globalSplit)
			globalSplit[key] = sid
		}
		units[i].splitID = sid
	}

	// stage 4b: per-flow session signatures (b1 client-only shape ids, b2 split).
	sessB1 := map[string]int{}
	sessB2 := map[string]int{}
	for _, fr := range flows {
		ids1 := make([]int, len(fr.unitRows))
		ids2 := make([]int, len(fr.unitRows))
		for k, uidx := range fr.unitRows {
			ids1[k] = units[uidx].shapeID
			ids2[k] = units[uidx].splitID
		}
		s1 := mine.SessionShape(ids1)
		if _, ok := sessB1[s1]; !ok {
			sessB1[s1] = len(sessB1)
		}
		s2 := mine.SessionShape(ids2)
		if _, ok := sessB2[s2]; !ok {
			sessB2[s2] = len(sessB2)
		}
	}
	elapsed := time.Since(t0)

	// ---- report ----
	nShapes := distinctInts(units, func(u unitRow) int { return u.shapeID })
	nSplits := distinctInts(units, func(u unitRow) int { return u.splitID })
	fmt.Printf("flows=%d units=%d elapsed=%.2fs\n", len(flows), len(units), elapsed.Seconds())
	fmt.Printf("per-request shapes (stage4a) = %d\n", nShapes)
	fmt.Printf("split-shapes (stage5)        = %d\n", nSplits)

	// ShapeStore parity: the streaming store must derive the same shape count.
	storeShapes := 0
	for _, svc := range services {
		storeShapes += store.ShapeCount(svc)
	}
	parity := "MATCH"
	if storeShapes != nShapes {
		parity = "MISMATCH"
	}
	fmt.Printf("shapestore per-request shapes = %d  (vs pure pipeline %d: %s)\n", storeShapes, nShapes, parity)
	fmt.Printf("session shapes: b1(client-only)=%d  b2(client+response)=%d\n", len(sessB1), len(sessB2))

	fmt.Println("\nper service:")
	fmt.Printf("  %-13s %6s %8s %10s\n", "svc", "units", "shapes", "splits")
	for _, svc := range services {
		nu, sh, sp := 0, map[int]bool{}, map[int]bool{}
		for _, u := range units {
			if u.svc == svc {
				nu++
				sh[u.shapeID] = true
				sp[u.splitID] = true
			}
		}
		fmt.Printf("  %-13s %6d %8d %10d\n", svc, nu, len(sh), len(sp))
	}

	// singleton rate + cover-90 of flag-leaving units, over per-request shapes
	// and over split-shapes. flag_present is the ground-truth-ish signal.
	fmt.Println("\nvalidation (flag_present as the flag-leaving signal):")
	reportGrouping("per-request shapes", units, func(u unitRow) int { return u.shapeID })
	reportGrouping("split-shapes      ", units, func(u unitRow) int { return u.splitID })

	// the flag_present oracle vs official flag_out, at the FLOW level.
	reportOracle(flows, units)

	_ = shapeTemplate
}

func reportGrouping(name string, units []unitRow, id func(unitRow) int) {
	total := map[int]int{}
	fp := map[int]int{}
	totalFP := 0
	for _, u := range units {
		g := id(u)
		total[g]++
		if u.flagPresent {
			fp[g]++
			totalFP++
		}
	}
	singles := 0
	for _, c := range total {
		if c == 1 {
			singles++
		}
	}
	// cover-90 of flag-leaving units
	counts := make([]int, 0, len(fp))
	for _, c := range fp {
		counts = append(counts, c)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(counts)))
	need := float64(totalFP) * 0.9
	acc, cover := 0, 0
	for _, c := range counts {
		if float64(acc) >= need {
			break
		}
		acc += c
		cover++
	}
	fmt.Printf("  %s: shapes=%d singletons=%d (%.1f%%) flag_present_units=%d cover90=%d shapes\n",
		name, len(total), singles, 100*float64(singles)/float64(len(total)), totalFP, cover)
}

func reportOracle(flows []flowRow, units []unitRow) {
	tp, fp, fn, tn := 0, 0, 0, 0
	for fi := range flows {
		anyFP := false
		for _, uidx := range flows[fi].unitRows {
			if units[uidx].flagPresent {
				anyFP = true
				break
			}
		}
		switch {
		case flows[fi].flagOut && anyFP:
			tp++
		case flows[fi].flagOut && !anyFP:
			fn++
		case !flows[fi].flagOut && anyFP:
			fp++
		default:
			tn++
		}
	}
	prec := float64(tp) / float64(max1(tp+fp))
	rec := float64(tp) / float64(max1(tp+fn))
	fmt.Printf("\nflow-level flag_present vs official flag_out: TP=%d FN=%d FP=%d TN=%d  precision=%.4f recall=%.4f\n",
		tp, fn, fp, tn, prec, rec)
}

func distinctInts(units []unitRow, id func(unitRow) int) int {
	seen := map[int]bool{}
	for _, u := range units {
		seen[id(u)] = true
	}
	return len(seen)
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
