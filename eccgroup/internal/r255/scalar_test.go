package r255

import (
	"testing"

	"github.com/cymony/cryptomony/internal/test"
)

func testCvtScalar(t *testing.T) {
	t.Helper()

	err := test.CheckPanic(func() {
		cvtScalar(nil)
	})
	test.CheckNoErr(t, err, "panic expected")
}

func testEqualScalar(t *testing.T, testTimes int, g *Group) {
	t.Helper()

	for i := 0; i < testTimes; i++ {
		Q := g.RandomScalar()

		if !(Q.Equal(nil) == 0) {
			test.Report(t, 1, 0, nil)
		}
	}
}

func testZeroScalar(t *testing.T, testTimes int, g *Group) {
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

func testOneScalar(t *testing.T, testTimes int, g *Group) {
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

func testRandomScalar(t *testing.T, testTimes int, g *Group) {
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

func testAddScalar(t *testing.T, testTimes int, g *Group) {
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

		gotnil := want.Add(nil)
		if !(gotnil.Equal(want) == 1) {
			test.Report(t, gotnil, want, nil)
		}
	}
}

func testSubScalar(t *testing.T, testTimes int, g *Group) {
	t.Helper()

	Q := g.NewScalar()

	for i := 0; i < testTimes; i++ {
		rnd := g.RandomScalar()
		Q.Set(rnd).Subtract(rnd)

		if !Q.IsZero() {
			test.Report(t, Q.IsZero(), true, "subtraction from itself is not equal to zero")
		}

		Z := g.RandomScalar()
		gotnil := Z.Subtract(nil)

		if !(gotnil.Equal(Z) == 1) {
			test.Report(t, gotnil, Z, nil)
		}
	}
}

func testMultiplyScalar(t *testing.T, testTimes int, g *Group) {
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

		Z := g.RandomScalar()
		gotnil := Z.Multiply(nil)

		if !gotnil.IsZero() {
			test.Report(t, gotnil, "zero", nil)
		}
	}
}

func testSetScalar(t *testing.T, testTimes int, g *Group) {
	t.Helper()

	for i := 0; i < testTimes; i++ {
		E := g.RandomScalar()
		Q := g.NewScalar()

		Q.Set(E)

		if !(Q.Equal(E) == 1) {
			test.Report(t, Q, E, E)
		}

		gotnil := Q.Set(nil)
		if !gotnil.IsZero() {
			test.Report(t, gotnil, "zero", "set nil should set to zero")
		}
	}
}

func testCopyScalar(t *testing.T, testTimes int, g *Group) {
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

func testEncodeAndDecodeScalar(t *testing.T, testTimes int, g *Group) {
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

func testMarshalScalar(t *testing.T, testTimes int, g *Group) {
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
