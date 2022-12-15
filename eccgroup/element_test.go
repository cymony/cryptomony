// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//nolint:gocyclo // tests and benchmarks can be complex
package eccgroup

import (
	"testing"

	"github.com/cymony/cryptomony/internal/test"
)

var allGroups = []Group{
	P256Sha256,
	P384Sha384,
	P521Sha512,
	Ristretto255Sha512,
}

func testBase(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewElement().Identity()

	for i := 0; i < testTimes; i++ {
		got := g.NewElement().Base()

		if Q.Equal(got) == 1 {
			test.Report(t, got, Q, "generator and identity are equal")
		}
	}
}

func testIdentity(t *testing.T, testTimes int, g Group) {
	t.Helper()

	for i := 0; i < testTimes; i++ {
		identity := g.NewElement().Identity()
		e := g.RandomElement()
		zero := g.NewElement().Set(e).Negate().Add(e)

		if !(zero.Equal(identity) == 1) {
			test.Report(t, zero, identity, "zero and identity are not equal")
		}
	}
}

func testAddAndDouble(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewElement()

	for i := 0; i < testTimes; i++ {
		P := g.RandomElement()

		got := Q.Set(P).Double().Double().Double().Double() // Q = 16P

		R := g.NewElement().Identity()
		for j := 0; j < 16; j++ {
			R.Add(P)
		}

		want := R // R = 16P = P+P...+P
		if !(got.Equal(want) == 1) {
			test.Report(t, got, want, P)
		}
	}
}

func testNegate(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewElement()

	for i := 0; i < testTimes; i++ {
		P := g.RandomElement()
		Q.Set(P).Negate()
		Q.Add(P)

		got := Q.IsIdentity()
		want := true

		if got != want {
			test.Report(t, got, want, P)
		}
	}
}

func testSub(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewElement().Identity()
	want := g.NewElement().Identity()

	for i := 0; i < testTimes; i++ {
		r := g.RandomElement()

		Q.Set(r)
		Q.Subtract(r)

		got := Q
		if !(got.Equal(want) == 1) {
			test.Report(t, got, want, "subtracting with itself is not equal")
		}
	}
}

func testMultiply(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewElement()
	inv := g.NewScalar()

	for i := 0; i < testTimes; i++ {
		P := g.RandomElement()
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

func testCopy(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewElement()

	for i := 0; i < testTimes; i++ {
		r := g.RandomElement()
		copied := r.Copy()
		Q.Set(copied)

		if !(Q.Equal(r) == 1) {
			test.Report(t, Q, r, "copied element and Q are not equal")
		}
	}
}

func testEncodeAndDecode(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewElement()

	for i := 0; i < testTimes; i++ {
		r := g.RandomElement()
		err := Q.Decode(r.Encode())
		test.CheckNoErr(t, err, "decode err")

		if !(Q.Equal(r) == 1) {
			test.Report(t, Q, r, "Q and R are not equal")
		}
	}
}

func testMarshal(t *testing.T, testTimes int, g Group) {
	t.Helper()

	Q := g.NewElement()

	for i := 0; i < testTimes; i++ {
		r := g.RandomElement()
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

func BenchmarkElement(b *testing.B) {
	for _, group := range allGroups {
		x := group.RandomElement()
		y := group.RandomElement()
		s := group.RandomScalar()

		name := group.String()
		// Base
		b.Run(name+"/Base", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Base()
			}
		})
		// Identity
		b.Run(name+"/Identity", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Identity()
			}
		})
		// Add
		b.Run(name+"/Add", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Add(y)
			}
		})
		// Double
		b.Run(name+"/Double", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Double()
			}
		})
		// Negate
		b.Run(name+"/Add", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Negate()
			}
		})
		// Sub
		x.Identity()
		b.Run(name+"/Subtract", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Subtract(y)
			}
		})
		// Multiply
		x = group.RandomElement()

		b.Run(name+"/Multiply", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Multiply(s)
			}
		})
		// Copy
		b.Run(name+"/Copy", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Copy()
			}
		})
		// Encode
		b.Run(name+"/Encode", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Encode()
			}
		})
		// Decode
		encoded := y.Encode()

		b.Run(name+"/Decode", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Decode(encoded) //nolint:errcheck // because of benchmark
			}
		})

		// MarshalBinary
		b.Run(name+"/MarshalBinary", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.MarshalBinary() //nolint:errcheck // because of benchmark
			}
		})
		// UnmarshalBinary
		marshaledB, err := y.MarshalBinary()
		test.CheckNoErr(b, err, "error should not returned while marshaling binary")
		b.Run(name+"/UnmarshalBinary", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.UnmarshalBinary(marshaledB) //nolint:errcheck // because of benchmark
			}
		})
		// MarshalText
		b.Run(name+"/MarshalText", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.MarshalText() //nolint:errcheck // because of benchmark
			}
		})
		// UnmarshalText
		marshaledT, err := y.MarshalBinary()
		test.CheckNoErr(b, err, "error should not returned while marshaling text")
		b.Run(name+"/UnmarshalText", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.UnmarshalText(marshaledT) //nolint:errcheck // because of benchmark
			}
		})
	}
}
