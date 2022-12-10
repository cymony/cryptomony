// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package eccgroup

import (
	"testing"

	"github.com/cymony/cryptomony/internal/test"
)

func testZeroScalar(t *testing.T, testTimes int, g Group) {
	t.Helper()

	got := g.NewScalar().Zero()

	for i := 0; i < testTimes; i++ {
		rnd := g.RandomScalar()
		want := g.NewScalar().Set(rnd).Subtract(rnd)

		if !(got.Equal(want) == 1) {
			test.Report(t, got, want, "zero func sets different value from zero")
		}
	}
}

func testOneScalar(t *testing.T, testTimes int, g Group) {
	t.Helper()

	got := g.NewScalar().One()

	for i := 0; i < testTimes; i++ {
		rnd := g.RandomScalar()
		inv := g.NewScalar().Set(rnd).Invert()
		want := rnd.Multiply(inv)

		if !(got.Equal(want) == 1) {
			test.Report(t, got, want, "one func sets different value from one")
		}
	}
}

func testRandomScalar(t *testing.T, testTimes int, g Group) {
	t.Helper()

	for i := 0; i < testTimes; i++ {
		Q := g.NewScalar().Random()

		got := Q.IsZero()
		want := false

		if got {
			test.Report(t, got, want, "random outputs to zero")
		}
	}
}

func testAddScalar(t *testing.T, testTimes int, g Group) {
	t.Helper()

	two := g.NewScalar().One().Add(g.NewScalar().One())
	Q := g.NewScalar()

	for i := 0; i < testTimes; i++ {
		P := g.RandomScalar()

		got := Q.Set(P).Multiply(two) // Q = 2P

		R := g.NewScalar().Zero()
		for j := 0; j < 2; j++ {
			R.Add(P)
		}

		want := R // R = 16P = P+P...+P
		if !(got.Equal(want) == 1) {
			test.Report(t, got, want, P)
		}
	}
}

func testSubScalar(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewScalar()

	for i := 0; i < testTimes; i++ {
		rnd := g.RandomScalar()
		Q.Set(rnd).Subtract(rnd)

		if !Q.IsZero() {
			test.Report(t, Q.IsZero(), true, "subtraction from itself is not equal to zero")
		}
	}
}

func testMultiplyScalar(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewScalar()
	inv := g.NewScalar()

	for i := 0; i < testTimes; i++ {
		P := g.RandomScalar()
		k := g.RandomScalar()
		inv.Set(k).Invert()

		Q.Set(P).Multiply(k)
		Q.Multiply(inv)

		got := P
		want := Q

		if !(got.Equal(want) == 1) {
			test.Report(t, got, want, P, k)
		}
	}
}

func testCopyScalar(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewScalar()

	for i := 0; i < testTimes; i++ {
		r := g.RandomScalar()
		copied := r.Copy()
		Q.Set(copied)

		if !(Q.Equal(r) == 1) {
			test.Report(t, Q, r, "copied element and Q are not equal")
		}
	}
}

func testEncodeAndDecodeScalar(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewScalar()

	for i := 0; i < testTimes; i++ {
		r := g.RandomScalar()
		err := Q.Decode(r.Encode())
		test.CheckNoErr(t, err, "decode err")

		if !(Q.Equal(r) == 1) {
			test.Report(t, Q, r, "Q and R are not equal")
		}
	}
}

func testMarshalScalar(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewScalar()

	for i := 0; i < testTimes; i++ {
		r := g.RandomScalar()
		// Test Marshal and Unmarshal Binary
		marshaledB, err := r.MarshalBinary()
		test.CheckNoErr(t, err, "error should not returned while marshaling binary")
		err = Q.UnmarshalBinary(marshaledB)
		test.CheckNoErr(t, err, "error should not returned while unmarshaling binary")

		if !(Q.Equal(r) == 1) {
			test.Report(t, Q, r, "Q and R is not equal after marshal and unmarshal binary")
		}

		marshaledT, err := r.MarshalText()
		test.CheckNoErr(t, err, "error should not returned while marshaling text")
		err = Q.UnmarshalText(marshaledT)
		test.CheckNoErr(t, err, "error should not returned while unmarshaling text")

		if !(Q.Equal(r) == 1) {
			test.Report(t, Q, r, "Q and R is not equal after marshal and unmarshal text")
		}
	}
}

//nolint:errcheck,gocyclo //benchmark
func BenchmarkScalar(b *testing.B) {
	for _, group := range allGroups {
		x := group.RandomScalar()
		y := group.RandomScalar()

		name := group.String()

		// Zero
		b.Run(name+"/Zero", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Zero()
			}
		})

		// One
		b.Run(name+"/One", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.One()
			}
		})

		// Add
		b.Run(name+"/Add", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Add(y)
			}
		})

		// Subtract
		b.Run(name+"/Subtract", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Subtract(y)
			}
		})

		// Set
		b.Run(name+"/Set", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Set(y)
			}
		})

		// Encode
		b.Run(name+"/Encode", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Encode()
			}
		})

		encodedY := y.Encode()
		// Decode
		b.Run(name+"/Decode", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Decode(encodedY)
			}
		})

		// Copy
		b.Run(name+"/Copy", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Copy()
			}
		})

		// Equal
		b.Run(name+"/Equal", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Equal(y)
			}
		})

		// Invert
		b.Run(name+"/Invert", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Invert()
			}
		})

		// IsZero
		b.Run(name+"/IsZero", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.IsZero()
			}
		})

		// Multiply
		b.Run(name+"/Multiply", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Multiply(y)
			}
		})

		// Random
		b.Run(name+"/Random", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Random()
			}
		})

		// MarshalBinary
		b.Run(name+"/MarshalBinary", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.MarshalBinary()
			}
		})

		marshalledY, err := y.MarshalBinary()
		test.CheckNoErr(b, err, "marshal binary err")

		// UnmarshalBinary
		b.Run(name+"/UnmarshalBinary", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.UnmarshalBinary(marshalledY)
			}
		})

		// MarshalText
		b.Run(name+"/MarshalText", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.MarshalText()
			}
		})

		marshalledTextY, err := y.MarshalText()
		test.CheckNoErr(b, err, "marshal text err")

		// UnmarshalText
		b.Run(name+"/UnmarshalText", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.UnmarshalText(marshalledTextY)
			}
		})
	}
}
