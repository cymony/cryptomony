// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package eccgroup

import "testing"

func TestElementAndScalar(t *testing.T) {
	const testTimes = 1 << 7

	for _, g := range allGroups {
		g := g
		n := g.String()

		t.Run(n+"/Scalar/Zero", func(tt *testing.T) { testZeroScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/One", func(tt *testing.T) { testOneScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/Random", func(tt *testing.T) { testRandomScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/Add", func(tt *testing.T) { testAddScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/Sub", func(tt *testing.T) { testSubScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/Multiply", func(tt *testing.T) { testMultiplyScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/Copy", func(tt *testing.T) { testCopyScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/EncodeAndDecode", func(tt *testing.T) { testEncodeAndDecodeScalar(tt, testTimes, g) })
		t.Run(n+"/Scalar/MarshalAndUnmarshal", func(tt *testing.T) { testMarshalScalar(t, testTimes, g) })

		t.Run(n+"/Element/Base", func(tt *testing.T) { testBase(tt, testTimes, g) })
		t.Run(n+"/Element/Identity", func(tt *testing.T) { testIdentity(tt, testTimes, g) })
		t.Run(n+"/Element/AddAndDouble", func(tt *testing.T) { testAddAndDouble(tt, testTimes, g) })
		t.Run(n+"/Element/Negate", func(tt *testing.T) { testNegate(tt, testTimes, g) })
		t.Run(n+"/Element/Sub", func(tt *testing.T) { testSub(tt, testTimes, g) })
		t.Run(n+"/Element/Multiply", func(tt *testing.T) { testMultiply(tt, testTimes, g) })
		t.Run(n+"/Element/Copy", func(tt *testing.T) { testCopy(tt, testTimes, g) })
		t.Run(n+"/Element/EncodeAndDecode", func(tt *testing.T) { testEncodeAndDecode(t, testTimes, g) })
		t.Run(n+"/Element/MarshalAndUnmarshal", func(tt *testing.T) { testMarshal(t, testTimes, g) })
	}
}
