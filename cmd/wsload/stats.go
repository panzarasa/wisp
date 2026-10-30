package main

import (
	"bufio"
	"cmp"
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"slices"
	"strings"
	"time"
)

// histogram counts latencies in nanoseconds with 128 sub-buckets per power
// of two: under 1% of error on any percentile, in a fixed 34 KiB.
type histogram struct {
	counts [(maxExp + 1) << subBits]uint64
	total  uint64
	max    uint64
}

const (
	subBits = 7
	maxExp  = 40 - subBits // values up to 2^40 ns, about 18 minutes
)

func newHistogram() *histogram { return new(histogram) }

func bucketOf(v uint64) int {
	if v < 1<<subBits {
		return int(v)
	}
	e := bits.Len64(v) - subBits - 1
	if e > maxExp-1 {
		return len(histogram{}.counts) - 1
	}
	return (e+1)<<subBits | int(v>>e)&(1<<subBits-1)
}

// valueOf is the midpoint of bucket i.
func valueOf(i int) uint64 {
	if i < 1<<subBits {
		return uint64(i)
	}
	e := i>>subBits - 1
	m := uint64(i&(1<<subBits-1) | 1<<subBits)
	return m<<e + (uint64(1)<<e)/2
}

func (h *histogram) record(d time.Duration) {
	v := uint64(max(d, 0))
	h.counts[bucketOf(v)]++
	h.total++
	h.max = max(h.max, v)
}

func (h *histogram) merge(o *histogram) {
	for i, c := range o.counts {
		h.counts[i] += c
	}
	h.total += o.total
	h.max = max(h.max, o.max)
}

// quantile returns the value under which a fraction q of the samples fall,
// in microseconds.
func (h *histogram) quantile(q float64) float64 {
	if h.total == 0 {
		return 0
	}
	rank := uint64(q*float64(h.total-1)) + 1
	var seen uint64
	for i, c := range h.counts {
		seen += c
		if seen >= rank {
			return float64(min(valueOf(i), h.max)) / 1e3
		}
	}
	return float64(h.max) / 1e3
}

func (h *histogram) fill(r *result) {
	r.P50 = h.quantile(0.50)
	r.P90 = h.quantile(0.90)
	r.P99 = h.quantile(0.99)
	r.P999 = h.quantile(0.999)
	r.Max = float64(h.max) / 1e3
}

// ---- summary ----------------------------------------------------------------

// printSummary prints, for each scenario and server, the median of the
// repetitions.
func printSummary(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	type key struct {
		mode               string
		conns, size, extra int
		rate               float64
		target             string
	}
	groups := map[key][]result{}
	var order []key
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var r result
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		k := key{r.Mode, r.Conns, r.Size, r.Pipeline + r.Window, r.TargetRate, r.Target}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	slices.SortStableFunc(order, func(a, b key) int {
		modes := []string{"echo", "chat", "idle"}
		if c := slices.Index(modes, a.mode) - slices.Index(modes, b.mode); c != 0 {
			return c
		}
		if a.size != b.size {
			return a.size - b.size
		}
		if a.extra != b.extra {
			return a.extra - b.extra
		}
		if a.rate != b.rate {
			return cmp.Compare(a.rate, b.rate)
		}
		if a.conns != b.conns {
			return a.conns - b.conns
		}
		return strings.Compare(a.target, b.target)
	})

	med := func(rs []result, f func(r result) float64) float64 {
		v := make([]float64, len(rs))
		for i, r := range rs {
			v[i] = f(r)
		}
		slices.Sort(v)
		if len(v)%2 == 1 {
			return v[len(v)/2]
		}
		return (v[len(v)/2-1] + v[len(v)/2]) / 2
	}

	fmt.Println("Mediana delle ripetizioni. CPU server: secondi di CPU per secondo di prova (1.00 = un core pieno).")
	mode := ""
	for _, k := range order {
		rs := groups[k]
		if k.mode != mode {
			mode = k.mode
			fmt.Println()
			switch mode {
			case "echo":
				fmt.Println("ECHO (messaggi binari; ritmo: msg/s chiesti a ritmo fisso, - = botta e risposta; latenza in microsecondi)")
				fmt.Printf("%-10s %6s %6s %5s %8s %4s %12s %8s %8s %8s %8s %8s\n",
					"server", "conn", "byte", "pipe", "ritmo", "rip", "msg/s", "p50", "p90", "p99", "p99.9", "CPU srv")
			case "chat":
				fmt.Println("CHAT (un mittente, ogni messaggio a tutti i membri; consegne/s e latenza in microsecondi)")
				fmt.Printf("%-10s %6s %6s %5s %4s %12s %8s %8s %8s %8s %8s\n",
					"server", "membri", "byte", "fin.", "rip", "consegne/s", "p50", "p90", "p99", "p99.9", "CPU srv")
			case "idle":
				fmt.Println("INATTIVE (connessioni aperte dopo un messaggio ciascuna)")
				fmt.Printf("%-10s %7s %4s %12s %12s %14s %12s\n",
					"server", "conn", "rip", "apertura s", "RSS MiB", "byte/conn", "CPU srv")
			}
		}
		switch mode {
		case "echo", "chat":
			if mode == "echo" {
				pace := "-"
				if k.rate > 0 {
					pace = fmt.Sprintf("%.0fk", k.rate/1000)
				}
				fmt.Printf("%-10s %6d %6d %5d %8s %4d", k.target, k.conns, k.size, k.extra, pace, len(rs))
			} else {
				fmt.Printf("%-10s %6d %6d %5d %4d", k.target, k.conns, k.size, k.extra, len(rs))
			}
			fmt.Printf(" %12.0f %8.0f %8.0f %8.0f %8.0f %8.2f\n",
				med(rs, func(r result) float64 { return r.Rate }),
				med(rs, func(r result) float64 { return r.P50 }),
				med(rs, func(r result) float64 { return r.P90 }),
				med(rs, func(r result) float64 { return r.P99 }),
				med(rs, func(r result) float64 { return r.P999 }),
				med(rs, func(r result) float64 { return r.ServerCPU / r.Seconds }))
		case "idle":
			fmt.Printf("%-10s %7d %4d %12.2f %12.1f %14.0f %12.3f\n",
				k.target, k.conns, len(rs),
				med(rs, func(r result) float64 { return r.ConnectSeconds }),
				med(rs, func(r result) float64 { return float64(r.ServerRSSEnd) / 1024 }),
				med(rs, func(r result) float64 { return r.BytesPerConn }),
				med(rs, func(r result) float64 { return r.ServerCPU / r.Seconds }))
		}
	}
	return nil
}
