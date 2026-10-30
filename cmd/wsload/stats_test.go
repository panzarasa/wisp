package main

import (
	"math"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

func TestBuckets(t *testing.T) {
	prev := -1
	for _, v := range []uint64{0, 1, 127, 128, 129, 255, 256, 1000, 1 << 20, 1<<20 + 1, 1<<40 - 1} {
		i := bucketOf(v)
		if i < prev {
			t.Fatalf("bucketOf(%d) = %d, below the previous bucket %d", v, i, prev)
		}
		prev = i
		if mid := valueOf(i); math.Abs(float64(mid)-float64(v)) > float64(v)/128+1 {
			t.Errorf("bucketOf(%d) = %d, whose midpoint %d is off by more than 1/128", v, i, mid)
		}
	}
	if i := bucketOf(math.MaxUint64); i != len(histogram{}.counts)-1 {
		t.Errorf("bucketOf(MaxUint64) = %d, want the last bucket", i)
	}
}

func TestQuantile(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	a, b := newHistogram(), newHistogram()
	var all []float64
	for i := range 100000 {
		d := time.Duration(r.ExpFloat64() * float64(200*time.Microsecond))
		if i%2 == 0 {
			a.record(d)
		} else {
			b.record(d)
		}
		all = append(all, float64(d)/1e3)
	}
	a.merge(b)
	slices.Sort(all)
	for _, q := range []float64{0.5, 0.9, 0.99, 0.999} {
		want := all[int(q*float64(len(all)-1))]
		if got := a.quantile(q); math.Abs(got-want) > want/100 {
			t.Errorf("quantile(%v) = %.2f µs, want %.2f µs within 1%%", q, got, want)
		}
	}
	if a.total != 100000 {
		t.Errorf("merged total %d, want 100000", a.total)
	}
	if got, want := a.quantile(1), all[len(all)-1]; math.Abs(got-want) > 0.001 {
		t.Errorf("quantile(1) = %.3f µs, want the maximum %.3f µs", got, want)
	}
}
