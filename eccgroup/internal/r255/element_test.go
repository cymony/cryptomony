// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package r255

import (
	"testing"

	"github.com/cymony/cryptomony/internal/test"
	"github.com/cymony/cryptomony/utils"
)

func testCvtEl(t *testing.T) {
	t.Helper()

	err := test.CheckPanic(func() {
		cvtEl(nil)
	})
	test.CheckNoErr(t, err, "panic expected")
}

func testEqualElement(t *testing.T, testTimes int, g *Group) {
	t.Helper()

	for i := 0; i < testTimes; i++ {
		Q := g.RandomElement()

		if !(Q.Equal(nil) == 0) {
			test.Report(t, 1, 0, nil)
		}
	}
}

func testBaseElement(t *testing.T, testTimes int, g *Group) {
	t.Helper()

	Q := g.NewElement().Identity()

	for i := 0; i < testTimes; i++ {
		got := g.NewElement().Base()

		if Q.Equal(got) == 1 {
			test.Report(t, got, Q, "generator and identity are equal")
		}
	}
}

func testIdentityElement(t *testing.T, testTimes int, g *Group) {
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

func testAddAndDoubleElement(t *testing.T, testTimes int, g *Group) {
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

		gotnil := want.Add(nil)

		if !(gotnil.Equal(want) == 1) {
			test.Report(t, gotnil, want, R)
		}
	}
}

func testNegateElement(t *testing.T, testTimes int, g *Group) {
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

func testSubElement(t *testing.T, testTimes int, g *Group) {
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

		gotnil := got.Subtract(nil)
		if !(gotnil.Equal(got) == 1) {
			test.Report(t, gotnil, got, "subtracting with nil should bu equal itself")
		}
	}
}

func testMultiplyElement(t *testing.T, testTimes int, g *Group) {
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

		Z := g.RandomElement()
		gotnil := Z.Multiply(nil)

		if !gotnil.IsIdentity() {
			test.Report(t, gotnil, "identity element", Z, nil)
		}
	}
}

func testSetElement(t *testing.T, testTimes int, g *Group) {
	t.Helper()

	for i := 0; i < testTimes; i++ {
		E := g.RandomElement()
		Q := g.NewElement()

		Q.Set(E)

		if !(Q.Equal(E) == 1) {
			test.Report(t, Q, E, E)
		}

		gotnil := Q.Set(nil)
		if !gotnil.IsIdentity() {
			test.Report(t, gotnil, "identity", "set nil should set to identity")
		}
	}
}

func testCopyElement(t *testing.T, testTimes int, g *Group) {
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

func testEncodeAndDecodeElement(t *testing.T, testTimes int, g *Group) {
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

	wrongSize := conanicalSize + 1
	data := utils.RandomBytes(wrongSize)

	err := Q.Decode(data)
	test.CheckIsErr(t, err, "error expected")
}

func testMarshalElement(t *testing.T, testTimes int, g *Group) {
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
