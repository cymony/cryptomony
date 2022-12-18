// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package eccgroup

import (
	"testing"

	"github.com/cymony/cryptomony/eccgroup/internal/nist"
	"github.com/cymony/cryptomony/eccgroup/internal/r255"
	"github.com/cymony/cryptomony/internal/test"
)

var allGroups = []Group{
	P256Sha256,
	P384Sha384,
	P521Sha512,
	Ristretto255Sha512,
}

func TestGroups(t *testing.T) {
	const testTimes = 1 << 7

	for _, g := range allGroups {
		g := g
		n := g.String()

		t.Run(n+"/Scalar/Equal", func(tt *testing.T) { testEqualScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/Zero", func(tt *testing.T) { testZeroScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/One", func(tt *testing.T) { testOneScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/Random", func(tt *testing.T) { testRandomScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/Add", func(tt *testing.T) { testAddScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/Sub", func(tt *testing.T) { testSubScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/Multiply", func(tt *testing.T) { testMultiplyScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/Copy", func(tt *testing.T) { testCopyScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/EncodeAndDecode", func(tt *testing.T) { testEncodeAndDecodeScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/MarshalAndUnmarshal", func(tt *testing.T) { testMarshalScalar(tt, testTimes, g) })

		t.Run(n+"/Element/Equal", func(tt *testing.T) { testEqual(tt, testTimes, g) })
		t.Run(n+"/Element/Base", func(tt *testing.T) { testBase(tt, testTimes, g) })
		t.Run(n+"/Element/Identity", func(tt *testing.T) { testIdentity(tt, testTimes, g) })
		t.Run(n+"/Element/AddAndDouble", func(tt *testing.T) { testAddAndDouble(tt, testTimes, g) })
		t.Run(n+"/Element/Negate", func(tt *testing.T) { testNegate(tt, testTimes, g) })
		t.Run(n+"/Element/Sub", func(tt *testing.T) { testSub(tt, testTimes, g) })
		t.Run(n+"/Element/Multiply", func(tt *testing.T) { testMultiply(tt, testTimes, g) })
		t.Run(n+"/Element/Copy", func(tt *testing.T) { testCopy(tt, testTimes, g) })
		t.Run(n+"/Element/EncodeAndDecode", func(tt *testing.T) { testEncodeAndDecode(tt, testTimes, g) })
		t.Run(n+"/Element/MarshalAndUnmarshal", func(tt *testing.T) { testMarshal(tt, testTimes, g) })

		t.Run(n+"/Group/Base", func(tt *testing.T) { testBaseGroup(tt, testTimes, g) })
		t.Run(n+"/Group/ScalarAndElementLength", func(tt *testing.T) { testLengthsGroup(tt, testTimes, g) })
	}

	t.Run("Group/checkDST", func(tt *testing.T) { testcheckDST(tt) })
	t.Run("Group/Available", func(tt *testing.T) { testAvailable(tt) })
}

func testBaseGroup(t *testing.T, _ int, g Group) {
	t.Helper()

	gBase := g.Base()
	eBase := g.NewElement().Base()

	if !(gBase.Equal(eBase) == 1) {
		test.Report(t, gBase, eBase, "base elements not equal")
	}
}

func testLengthsGroup(t *testing.T, _ int, g Group) {
	t.Helper()

	switch g.get().Ciphersuite() {
	case r255.R255().Ciphersuite():
		test.CheckOk(t, r255.R255().ScalarLength() == g.ScalarLength(), "scalar length mismatch")
		test.CheckOk(t, r255.R255().ElementLength() == g.ElementLength(), "element length mismatch")
	case nist.P256().Ciphersuite():
		test.CheckOk(t, nist.P256().ScalarLength() == g.ScalarLength(), "scalar length mismatch")
		test.CheckOk(t, nist.P256().ElementLength() == g.ElementLength(), "element length mismatch")
	case nist.P384().Ciphersuite():
		test.CheckOk(t, nist.P384().ScalarLength() == g.ScalarLength(), "scalar length mismatch")
		test.CheckOk(t, nist.P384().ElementLength() == g.ElementLength(), "element length mismatch")
	case nist.P521().Ciphersuite():
		test.CheckOk(t, nist.P521().ScalarLength() == g.ScalarLength(), "scalar length mismatch")
		test.CheckOk(t, nist.P521().ElementLength() == g.ElementLength(), "element length mismatch")
	default:
		t.Error("unrecognized group")
	}
}

func testcheckDST(t *testing.T) {
	t.Helper()

	err := test.CheckPanic(func() {
		dst := []byte{}
		checkDST(dst)
	})
	test.CheckNoErr(t, err, "panic expected")
}

func testAvailable(t *testing.T) {
	t.Helper()

	for _, g := range allGroups {
		test.CheckOk(t, g.Available(), "groups should be available")
	}

	test.CheckOk(t, !maxID.Available(), "maxID should not be available")

	err := test.CheckPanic(func() {
		maxID.get()
	})
	test.CheckNoErr(t, err, "panic expected")
}
