// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package nist

import (
	"math/big"

	"github.com/cymony/cryptomony/h2f"
	"github.com/cymony/cryptomony/hash"
)

func s2int(s string) *big.Int {
	if p, _ := new(big.Int).SetString(s, 0); p != nil {
		return p
	}

	panic("invalid string to convert")
}

type mapping struct {
	z         *big.Int
	secLength int
	hash      hash.Hashing
}

type curve[point nistECGenericPoint[point]] struct {
	field    *field
	a, b     *big.Int
	NewPoint func() point
	mapping
}

func (c *curve[point]) setMapping(h hash.Hashing, z string, secLength int) {
	c.mapping.hash = h
	c.mapping.secLength = secLength
	c.mapping.z = s2int(z)
}

func (c *curve[point]) setCurveParams(prime *big.Int, a, b string, newPoint func() point) {
	c.field = newField(prime)
	c.a = s2int(a)
	c.b = s2int(b)
	c.NewPoint = newPoint
}

func (c *curve[point]) encodeToCurveXMD(input, dst []byte) point {
	u, err := h2f.Hash2FieldXMD(c.hash, input, dst, 1, 1, c.secLength, c.field.primeNumber)
	if err != nil {
		panic(err)
	}

	q := c.map2curveSSWU(u[0])

	return q
}

func (c *curve[point]) hashToCurveXMD(input, dst []byte) point {
	count := 2
	ext := 2

	u, err := h2f.Hash2FieldXMD(c.hash, input, dst, count, ext, c.secLength, c.field.primeNumber)
	if err != nil {
		panic(err)
	}

	q0 := c.map2curveSSWU(u[0])
	q1 := c.map2curveSSWU(u[1])

	return q0.Add(q0, q1)
}

// sqrtRatio3mod4 optimized sqrt_ratio function for q = 3 mod 4 curves.
// See https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html Appendinx F.2.1.2.
func (c *curve[point]) sqrtRatio3mod4(u, v *big.Int) (bool, *big.Int) {
	//nolint:gocritic // it is not commented code
	// c1 = (q-3) / 4
	c1 := new(big.Int)
	c1.Sub(c.field.primeNumber, big.NewInt(3)) //nolint:gomnd //no need constant
	c1.Rsh(c1, 2)                              //nolint:gomnd //no need constant

	// c2 = sqrt(-Z)
	nZ := c.field.neg(new(big.Int), c.z)
	c2 := c.field.sqrt(new(big.Int), nZ)

	// 1. tv1 = v^2
	tv1 := c.field.square(new(big.Int), v)
	// 2. tv2 = u * v
	tv2 := c.field.mul(new(big.Int), u, v)
	// 3. tv1 = tv1 * tv2
	tv1 = c.field.mul(tv1, tv1, tv2)
	// 4. y1 = tv1^c1
	y1 := c.field.exponent(new(big.Int), tv1, c1)
	// 5. y1 = y1 * tv2
	y1 = c.field.mul(y1, y1, tv2)
	// 6. y2 = y1 * c2
	y2 := c.field.mul(new(big.Int), y1, c2)
	// 7. tv3 = y1^2
	tv3 := c.field.square(new(big.Int), y1)
	// 8. tv3 = tv3 * v
	tv3 = c.field.mul(tv3, tv3, v)
	// 9. isQR = tv3 == u
	isQR := tv3.Cmp(u) == 0
	// 10. y = CMOV(y2, y1, isQR)
	y := c.field.cmov(new(big.Int), y2, y1, isQR)
	// 11. return (isQR, y)
	return isQR, y
}

// map2curveSSWU implements simplied swu method.
// See https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html Appendinx F.2.
func (c *curve[point]) map2curveSSWU(u *big.Int) point {
	// 1.  tv1 = u^2
	tv1 := c.field.square(new(big.Int), u)
	// 2.  tv1 = Z * tv1
	tv1 = c.field.mul(tv1, c.z, tv1)
	// 3.  tv2 = tv1^2
	tv2 := c.field.square(new(big.Int), tv1)
	// 4.  tv2 = tv2 + tv1
	tv2 = c.field.add(tv2, tv2, tv1)
	// 5.  tv3 = tv2 + 1
	tv3 := c.field.add(new(big.Int), tv2, one)
	// 6.  tv3 = B * tv3
	tv3 = c.field.mul(tv3, c.b, tv3)
	// 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	tv4 := c.field.cmov(new(big.Int), c.z, c.field.neg(new(big.Int), tv2), !c.field.isZero(tv2))
	// 8.  tv4 = A * tv4
	tv4 = c.field.mul(tv4, c.a, tv4)
	// 9.  tv2 = tv3^2
	tv2 = c.field.square(tv2, tv3)
	// 10. tv6 = tv4^2
	tv6 := c.field.square(new(big.Int), tv4)
	// 11. tv5 = A * tv6
	tv5 := c.field.mul(new(big.Int), c.a, tv6)
	// 12. tv2 = tv2 + tv5
	tv2 = c.field.add(tv2, tv2, tv5)
	// 13. tv2 = tv2 * tv3
	tv2 = c.field.mul(tv2, tv2, tv3)
	// 14. tv6 = tv6 * tv4
	tv6 = c.field.mul(tv6, tv6, tv4)
	// 15. tv5 = B * tv6
	tv5 = c.field.mul(tv5, c.b, tv6)
	// 16. tv2 = tv2 + tv5
	tv2 = c.field.add(tv2, tv2, tv5)
	// 17.   x = tv1 * tv3
	x := c.field.mul(new(big.Int), tv1, tv3)
	//nolint:gocritic // it is not commented code
	// 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
	isGx1Square, y1 := c.sqrtRatio3mod4(tv2, tv6)
	// 19.   y = tv1 * u
	y := c.field.mul(new(big.Int), tv1, u)
	// 20.   y = y * y1
	y = c.field.mul(y, y, y1)
	// 21.   x = CMOV(x, tv3, is_gx1_square)
	x = c.field.cmov(x, x, tv3, isGx1Square)
	// 22.   y = CMOV(y, y1, is_gx1_square)
	y = c.field.cmov(y, y, y1, isGx1Square)
	// 23.  e1 = sgn0(u) == sgn0(y)
	e1 := c.field.sgn0(u) == c.field.sgn0(y)
	// 24.   y = CMOV(-y, y, e1)
	y = c.field.cmov(y, c.field.neg(new(big.Int), y), y, e1)
	// 25.   x = x / tv4
	tv4 = c.field.inv(tv4, tv4)
	x = c.field.mul(x, x, tv4)

	return c.affineToPoint(x, y)
}

var (
	decompressed256 = [65]byte{0x04}
	decompressed384 = [97]byte{0x04}
	decompressed521 = [133]byte{0x04}
)

func (c *curve[point]) affineToPoint(pxc, pyc *big.Int) point {
	var decompressed []byte

	byteLen := (c.field.bitLen() + 7) / 8 //nolint:gomnd //no need constant
	switch byteLen {
	case 32: //nolint:gomnd //no need constant
		decompressed = decompressed256[:]
	case 48: //nolint:gomnd //no need constant
		decompressed = decompressed384[:]
	case 66: //nolint:gomnd //no need constant
		decompressed = decompressed521[:]
	default:
		panic("invalid byte length")
	}

	decompressed[0] = 0x04
	pxc.FillBytes(decompressed[1 : 1+byteLen])
	pyc.FillBytes(decompressed[1+byteLen:])

	p, err := c.NewPoint().SetBytes(decompressed)
	if err != nil {
		panic(err)
	}

	return p
}
