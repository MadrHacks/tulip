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
	"regexp"
	"sort"
	"strconv"
	"strings"
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
	// same segmented units + response features, one flow at a time. The cardinality
	// refinement knobs are overridable from the environment so the crispness metrics
	// below can be swept (MINECORE_SPLIT_CARD=K, MINECORE_SPLIT_VARIANTS=cap).
	store := mine.NewShapeStore(0)
	store.SetSplitParams(envInt("MINECORE_SPLIT_CARD", 0), envInt("MINECORE_SPLIT_VARIANTS", 0))

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
		store.Observe(svc, fl.Units, flFeats, r.FlagIn, r.Port, int64(fidx))
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

	// crispness metrics: baseline (raw Drain shapes) vs after cardinality
	// refinement, per service + totals. Uses the streaming store's variant
	// reservoir (populated by store.Observe above).
	reportCrispness(store)

	// the flag_present oracle vs official flag_out, at the FLOW level.
	reportOracle(flows, units)

	// Replay templates: synthesize the per-shape replay template (align.go
	// multiple-alignment over each shape's raw-sample reservoir + slot-typing)
	// and print the structure for the top flag_present shapes. This dataset
	// carries no live flagId set, so flagId positions type as random/unknown —
	// but the sanity check is that the VARYING positions land in Var slots while
	// the skeleton (endpoint/method) stays Const.
	flagRe := regexp.MustCompile(`[A-Z0-9]{31}=`)
	store.SynthesizeTemplates(flagRe, map[string]bool{})
	reportTemplates(store)

	_ = shapeTemplate
}

// reportTemplates prints the synthesized replay template for the top few
// flag_present shapes per service: the grouping skeleton alongside the aligned
// Const/Var structure, so the flagId/random positions (Var slots) can be eyeballed
// against the constant endpoint anchors.
func reportTemplates(store *mine.ShapeStore) {
	fmt.Println("\nsynthesized replay templates (top flag_present shapes per service):")
	for _, svc := range services {
		shapes := store.Shapes(svc)
		sort.Slice(shapes, func(i, j int) bool {
			if shapes[i].Signals.FlagPresent != shapes[j].Signals.FlagPresent {
				return shapes[i].Signals.FlagPresent > shapes[j].Signals.FlagPresent
			}
			return shapes[i].Members > shapes[j].Members
		})
		shown := 0
		for _, sh := range shapes {
			if sh.Signals.FlagPresent == 0 {
				break
			}
			tpl := store.ShapeTemplate(svc, sh.TemplateID)
			if tpl == nil {
				continue
			}
			fmt.Printf("  [%s shape %d] members=%d flag_present=%d segs=%d slots=%d\n",
				svc, sh.TemplateID, sh.Members, sh.Signals.FlagPresent, len(tpl.Segments), len(tpl.Slots))
			fmt.Printf("    skeleton: %s\n", sh.Template)
			fmt.Printf("    template: %s\n", renderTemplate(tpl))
			shown++
			if shown >= 3 {
				break
			}
		}
		if shown == 0 {
			fmt.Printf("  [%s] no templated flag_present shapes (below quorum or no shared structure)\n", svc)
		}
	}
}

// renderTemplate renders an aligned template as inline text: Const segments as
// quoted previews, Var segments as <VAR#i type charclass len=lo-hi> markers.
func renderTemplate(tpl *mine.Template) string {
	var b strings.Builder
	slot := 0
	for _, s := range tpl.Segments {
		if s.Var {
			if slot < len(tpl.Slots) {
				sl := tpl.Slots[slot]
				b.WriteString("<VAR#" + strconv.Itoa(slot) + " " + sl.Type.String())
				if sl.Charclass != "" {
					b.WriteString(" " + sl.Charclass)
				}
				b.WriteString(" len=" + strconv.Itoa(sl.MinLen) + "-" + strconv.Itoa(sl.MaxLen) + ">")
			} else {
				b.WriteString("<VAR>")
			}
			slot++
			continue
		}
		b.WriteString(previewConst(s.Const))
	}
	return b.String()
}

// previewConst renders constant bytes as a short, whitespace-escaped quoted
// preview so a template line stays readable.
func previewConst(c []byte) string {
	const max = 48
	s := string(c)
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\t", "\\t")
	if len(s) > max {
		s = s[:max] + "…"
	}
	return "«" + s + "»"
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

// reportCrispness prints the crispness metrics baseline (raw Drain shapes) vs
// after cardinality refinement, per service and in total. The metrics measure
// whether the shape set is CRISP — neither over-merged (a <*> sitting on a
// structural low-card position) nor under-merged (distinct shapes that value-
// masking says are the same interaction). All are protocol-agnostic.
func reportCrispness(store *mine.ShapeStore) {
	splitCard := envInt("MINECORE_SPLIT_CARD", 0)
	if splitCard <= 0 {
		splitCard = 4 // mirrors defaultSplitCard
	}
	fmt.Printf("\ncrispness metrics (baseline raw Drain shapes -> after cardinality refinement, K=%d):\n", splitCard)
	fmt.Printf("  %-13s %13s %13s %13s %13s %13s %8s\n",
		"svc", "shapes b->a", "singl% b->a", "overmrg b->a", "undermrg b->a", "exfil90 b->a", "overflow")

	var tBS, tAS, tBSing, tASing, tBOver, tAOver, tBUnder, tAUnder, tBExfil, tAExfil, tOver int
	for _, svc := range services {
		parents := store.Shapes(svc)
		refined := store.RefinedShapes(svc)
		m := crispRow(parents, refined)
		overflow := store.OverflowShapes(svc)
		printCrispRow(svc, m, overflow)

		tBS += m.baseShapes
		tAS += m.refShapes
		tBSing += m.baseSingle
		tASing += m.refSingle
		tBOver += m.baseOver
		tAOver += m.refOver
		tBUnder += m.baseUnder
		tAUnder += m.refUnder
		tBExfil += m.baseExfil
		tAExfil += m.refExfil
		tOver += overflow
	}
	printCrispRow("TOTAL", crispMetrics{
		baseShapes: tBS, refShapes: tAS, baseSingle: tBSing, refSingle: tASing,
		baseOver: tBOver, refOver: tAOver, baseUnder: tBUnder, refUnder: tAUnder,
		baseExfil: tBExfil, refExfil: tAExfil,
	}, tOver)
	fmt.Println("  metric key: overmrg = shapes with a <*> on a low-card (structural) position;",
		"undermrg = pairs of shapes identical after re-masking; exfil90 = shapes covering 90% of flag_present units")
}

// crispMetrics holds one service's baseline (b) and after-refinement (a) numbers.
type crispMetrics struct {
	baseShapes, refShapes int
	baseSingle, refSingle int
	baseOver, refOver     int
	baseUnder, refUnder   int
	baseExfil, refExfil   int
}

// crispRow computes the crispness metrics for one service from its parent (raw
// Drain) shapes and its refined (un-merged) shapes.
func crispRow(parents []mine.Shape, refined []mine.RefinedShape) crispMetrics {
	byParent := map[int][]mine.RefinedShape{}
	for _, r := range refined {
		byParent[r.ParentID] = append(byParent[r.ParentID], r)
	}
	var m crispMetrics
	m.baseShapes = len(parents)
	baseTemplates := make([]string, 0, len(parents))
	baseFlag := make([]int, 0, len(parents))
	for _, p := range parents {
		baseTemplates = append(baseTemplates, p.Template)
		baseFlag = append(baseFlag, p.Signals.FlagPresent)
		if p.Members == 1 {
			m.baseSingle++
		}
		// A parent is over-merged if refinement changed it: it either split into
		// several sub-shapes or its template lost a <*> on a structural position.
		g := byParent[p.TemplateID]
		if len(g) > 1 || (len(g) == 1 && g[0].Template != p.Template) {
			m.baseOver++
		}
	}
	m.baseUnder = undermergePairs(baseTemplates)
	m.baseExfil = cover90(baseFlag)

	m.refShapes = len(refined)
	refTemplates := make([]string, 0, len(refined))
	refFlag := make([]int, 0, len(refined))
	for _, r := range refined {
		refTemplates = append(refTemplates, r.Template)
		refFlag = append(refFlag, r.Signals.FlagPresent)
		if r.Members == 1 {
			m.refSingle++
		}
		if r.LowCardWild { // residual over-merge after refinement (want 0)
			m.refOver++
		}
	}
	m.refUnder = undermergePairs(refTemplates)
	m.refExfil = cover90(refFlag)
	return m
}

func printCrispRow(svc string, m crispMetrics, overflow int) {
	pct := func(n, d int) float64 {
		if d == 0 {
			return 0
		}
		return 100 * float64(n) / float64(d)
	}
	fmt.Printf("  %-13s %5d->%-6d %5.1f->%-6.1f %5d->%-6d %5d->%-6d %5d->%-6d %8d\n",
		svc,
		m.baseShapes, m.refShapes,
		pct(m.baseSingle, m.baseShapes), pct(m.refSingle, m.refShapes),
		m.baseOver, m.refOver,
		m.baseUnder, m.refUnder,
		m.baseExfil, m.refExfil,
		overflow)
}

// undermergePairs counts unordered pairs of shapes (by template) that collapse to
// the same string after re-applying value masking (mine.RemaskTemplate) — the
// under-merge / over-fragmentation probe. Shapes whose templates already differ
// only in a value position (an id that slipped past masking) are the target.
func undermergePairs(templates []string) int {
	buckets := map[string]int{}
	for _, t := range templates {
		buckets[mine.RemaskTemplate(t)]++
	}
	pairs := 0
	for _, n := range buckets {
		if n > 1 {
			pairs += n * (n - 1) / 2
		}
	}
	return pairs
}

// cover90 returns how many shapes (largest flag_present counts first) it takes to
// cover 90% of all flag_present units — the exfil-consolidation metric (want
// small: the leak concentrates in few shapes).
func cover90(flagCounts []int) int {
	total := 0
	for _, c := range flagCounts {
		total += c
	}
	if total == 0 {
		return 0
	}
	sorted := append([]int(nil), flagCounts...)
	sort.Sort(sort.Reverse(sort.IntSlice(sorted)))
	need := float64(total) * 0.9
	acc, cover := 0, 0
	for _, c := range sorted {
		if float64(acc) >= need {
			break
		}
		acc += c
		cover++
	}
	return cover
}

// envInt reads an integer environment variable, returning def when unset or
// unparseable.
func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
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
