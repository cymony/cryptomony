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
