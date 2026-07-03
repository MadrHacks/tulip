package mine

import "math"

const (
	minSamples      = 5
	validateSamples = 8
	covThreshold    = 0.35
	maxConfidence   = 0.95
)

// Obs is one observed inbound flow to a service: its source key (e.g. a /24
// subnet string), arrival time, and whether a flag left us in it.
type Obs struct {
	Source     string
	UnixSec    int64
	HasFlagOut bool
}

// Calibration is the learned SLA-checker fingerprint for a service.
type Calibration struct {
	Source     string
	PeriodSec  float64
	Validated  bool
	Confidence float64
	samples    int
}

type sourceStat struct {
	count    int
	flagOuts int
	lastSeen int64
	hasLast  bool
	gapSum   float64
	gapSqSum float64
	gapCount int
}

func (s *sourceStat) observe(o Obs) {
	s.count++
	if o.HasFlagOut {
		s.flagOuts++
	}
	if s.hasLast {
		gap := float64(o.UnixSec - s.lastSeen)
		s.gapSum += gap
		s.gapSqSum += gap * gap
		s.gapCount++
	}
	s.lastSeen = o.UnixSec
	s.hasLast = true
}

func (s *sourceStat) meanGap() float64 {
	if s.gapCount == 0 {
		return 0
	}
	return s.gapSum / float64(s.gapCount)
}

// cov is the coefficient of variation of inter-arrival gaps.
func (s *sourceStat) cov() float64 {
	if s.gapCount < 2 {
		return math.Inf(1)
	}
	mean := s.meanGap()
	if mean <= 0 {
		return math.Inf(1)
	}
	variance := s.gapSqSum/float64(s.gapCount) - mean*mean
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance) / mean
}

func (s *sourceStat) regular() bool {
	return s.gapCount >= 1 && s.cov() <= covThreshold
}

// Calibrator accumulates per-source stats from observed flows to one service.
type Calibrator struct {
	stats map[string]*sourceStat
}

func NewCalibrator() *Calibrator {
	return &Calibrator{stats: make(map[string]*sourceStat)}
}

// evictStale drops sources not seen since before, returning their keys. The
// checker probes every tick so it is always within the horizon and never
// evicted; quiet attacker/noise sources are what leave, keeping the map bounded.
func (c *Calibrator) evictStale(before int64) []string {
	var gone []string
	for src, s := range c.stats {
		if s.lastSeen < before {
			delete(c.stats, src)
			gone = append(gone, src)
		}
	}
	return gone
}

func (c *Calibrator) Observe(o Obs) {
	if c.stats == nil {
		c.stats = make(map[string]*sourceStat)
	}
	s := c.stats[o.Source]
	if s == nil {
		s = &sourceStat{}
		c.stats[o.Source] = s
	}
	s.observe(o)
}

// sourceSnapshot is a per-source stat row, the durable form of the calibrator so
// checker discrimination survives a restart instead of cold-starting.
type sourceSnapshot struct {
	source   string
	count    int
	flagOuts int
	lastSeen int64
	hasLast  bool
	gapSum   float64
	gapSqSum float64
	gapCount int
}

func (c *Calibrator) snapshot() []sourceSnapshot {
	out := make([]sourceSnapshot, 0, len(c.stats))
	for src, s := range c.stats {
		out = append(out, sourceSnapshot{
			source: src, count: s.count, flagOuts: s.flagOuts,
			lastSeen: s.lastSeen, hasLast: s.hasLast,
			gapSum: s.gapSum, gapSqSum: s.gapSqSum, gapCount: s.gapCount,
		})
	}
	return out
}

func restoreCalibrator(snaps []sourceSnapshot) *Calibrator {
	c := NewCalibrator()
	for _, s := range snaps {
		c.stats[s.source] = &sourceStat{
			count: s.count, flagOuts: s.flagOuts,
			lastSeen: s.lastSeen, hasLast: s.hasLast,
			gapSum: s.gapSum, gapSqSum: s.gapSqSum, gapCount: s.gapCount,
		}
	}
	return c
}

// Model picks the checker: among candidate sources (enough samples, zero
// flag-outs, regular cadence) it chooses the one with the most observations.
func (c *Calibrator) Model() Calibration {
	var best *sourceStat
	var bestSource string
	for src, s := range c.stats {
		if s.count < minSamples || s.flagOuts != 0 || !s.regular() {
			continue
		}
		if best == nil || s.count > best.count {
			best = s
			bestSource = src
		}
	}
	if best == nil {
		return Calibration{}
	}
	validated := best.count >= validateSamples
	conf := math.Min(maxConfidence, float64(best.count)/float64(validateSamples)*maxConfidence)
	return Calibration{
		Source:     bestSource,
		PeriodSec:  best.meanGap(),
		Validated:  validated,
		Confidence: conf,
		samples:    best.count,
	}
}

// SignalsFor builds the Signals for a flow given the learned model.
func (c Calibration) SignalsFor(source string, hasFlagOut bool) Signals {
	return Signals{
		SrcInCheckerSubnet: source == c.Source && c.Source != "",
		HasFlagOut:         hasFlagOut,
		Periodic:           c.Validated,
	}
}

// AsModel exposes the calibration as a CheckerModel.
func (c Calibration) AsModel() CheckerModel {
	return CheckerModel{Validated: c.Validated, Confidence: c.Confidence}
}
