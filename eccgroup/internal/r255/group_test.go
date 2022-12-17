package r255

import (
	"math/rand"
	"testing"

	"github.com/cymony/cryptomony/internal/test"
	"github.com/cymony/cryptomony/utils"
)

func TestR255(t *testing.T) {
	const testTimes = 1 << 7

	g, ok := R255().(*Group)
	test.CheckOk(t, ok, "type assertion err")

	t.Run("Scalar/CvtScalar", func(tt *testing.T) { testCvtScalar(tt) })
	t.Run("Scalar/Equal", func(tt *testing.T) { testEqualScalar(tt, testTimes, g) })
	t.Run("Scalar/Zero", func(tt *testing.T) { testZeroScalar(tt, testTimes, g) })
	t.Run("Scalar/One", func(tt *testing.T) { testOneScalar(tt, testTimes, g) })
	t.Run("Scalar/Random", func(tt *testing.T) { testRandomScalar(tt, testTimes, g) })
	t.Run("Scalar/Add", func(tt *testing.T) { testAddScalar(tt, testTimes, g) })
	t.Run("Scalar/Sub", func(tt *testing.T) { testSubScalar(tt, testTimes, g) })
	t.Run("Scalar/Multiply", func(tt *testing.T) { testMultiplyScalar(tt, testTimes, g) })
	t.Run("Scalar/Set", func(tt *testing.T) { testSetScalar(tt, testTimes, g) })
	t.Run("Scalar/Copy", func(tt *testing.T) { testCopyScalar(tt, testTimes, g) })
	t.Run("Scalar/EncodeAndDecode", func(tt *testing.T) { testEncodeAndDecodeScalar(tt, testTimes, g) })
	t.Run("Scalar/MarshalAndUnmarshal", func(tt *testing.T) { testMarshalScalar(tt, testTimes, g) })

	t.Run("Element/CvtEl", func(tt *testing.T) { testCvtEl(tt) })
	t.Run("Element/Equal", func(tt *testing.T) { testEqualElement(t, testTimes, g) })
	t.Run("Element/Base", func(tt *testing.T) { testBaseElement(t, testTimes, g) })
	t.Run("Element/Identity", func(tt *testing.T) { testIdentityElement(tt, testTimes, g) })
	t.Run("Element/AddAndDouble", func(tt *testing.T) { testAddAndDoubleElement(tt, testTimes, g) })
	t.Run("Element/Negate", func(tt *testing.T) { testNegateElement(tt, testTimes, g) })
	t.Run("Element/Sub", func(tt *testing.T) { testSubElement(tt, testTimes, g) })
	t.Run("Element/Multiply", func(tt *testing.T) { testMultiplyElement(tt, testTimes, g) })
	t.Run("Element/Set", func(tt *testing.T) { testSetElement(tt, testTimes, g) })
	t.Run("Element/Copy", func(tt *testing.T) { testCopyElement(tt, testTimes, g) })
	t.Run("Element/EncodeAndDecode", func(tt *testing.T) { testEncodeAndDecodeElement(tt, testTimes, g) })
	t.Run("Element/MarshalAndUnmarshal", func(tt *testing.T) { testMarshalElement(tt, testTimes, g) })

	t.Run("Group/Base", func(tt *testing.T) { testBaseGroup(t, testTimes, g) })
	t.Run("Group/HashToScalarAndGroup", func(tt *testing.T) { testHashToXGroup(t, g) })
}

func testBaseGroup(t *testing.T, testTimes int, g *Group) {
	t.Helper()

	want := g.NewElement().Base()

	for i := 0; i < testTimes; i++ {
		got := g.Base()

		if !(got.Equal(want) == 1) {
			test.Report(t, got, want, "base are different")
		}
	}
}

func testHashToXGroup(t *testing.T, g *Group) {
	t.Helper()

	tests := []struct {
		input     []byte
		dst       []byte
		wantPanic bool
	}{
		{
			input:     utils.RandomBytes(rand.Intn(15)), //nolint:gosec //for test
			dst:       []byte("This is greater than recommended length"),
			wantPanic: false,
		},
		{
			input:     utils.RandomBytes(rand.Intn(30)), //nolint:gosec //for test
			dst:       []byte{},
			wantPanic: true,
		},
		{
			input:     utils.RandomBytes(rand.Intn(20)), //nolint:gosec //for test
			dst:       []byte("shorter"),
			wantPanic: true,
		},
	}

	for _, tst := range tests {
		if tst.wantPanic {
			err := test.CheckPanic(func() {
				g.HashToScalar(tst.input, tst.dst)
			})
			test.CheckNoErr(t, err, "panic expected")

			err = test.CheckPanic(func() {
				g.EncodeToGroup(tst.input, tst.dst)
			})
			test.CheckNoErr(t, err, "panic expected")
		} else {
			err := test.CheckPanic(func() {
				sc := g.HashToScalar(tst.input, tst.dst)
				el := g.EncodeToGroup(tst.input, tst.dst)

				if len(sc.Encode()) != int(g.ScalarLength()) {
					test.Report(t, len(sc.Encode()), g.ScalarLength())
				}

				if len(el.Encode()) != int(g.ElementLength()) {
					test.Report(t, len(el.Encode()), g.ElementLength())
				}
			})
			test.CheckIsErr(t, err, "panic not expected")
		}
	}
}
