// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package nist

import (
	"crypto/rand"
	"math/big"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2) //nolint:gomnd //no need constant
)

type field struct {
	primeNumber *big.Int // p
	pMinus1Div2 *big.Int // p-1 / 2^1
	pMinus2     *big.Int // p-2
	exp         *big.Int
}

func newField(primeNumber *big.Int) *field {
	// pMinus1div2 is used to determine whether a big Int is a quadratic square.
	pMinus1Div2 := new(big.Int)
	pMinus1Div2.Sub(primeNumber, one)
	pMinus1Div2.Rsh(pMinus1Div2, 1)

	// pMinus2 is used for modular inversion.
	pMinus2 := new(big.Int)
	pMinus2.Sub(primeNumber, two)

	// precompute e = (p + 1) / 4
	exp := new(big.Int)
	exp.Add(primeNumber, one)
	exp.Rsh(exp, 2) //nolint:gomnd //no need constant

	return &field{
		primeNumber: primeNumber,
		pMinus1Div2: pMinus1Div2,
		pMinus2:     pMinus2,
		exp:         exp,
	}
}

// // one sets x to big.NewInt(1), returns x
// func (f field) one(x *big.Int) *big.Int {
// 	return x.Set(utils.One)
// }

// random sets x to cryptographically secure random, returns x.
func (f field) random(x *big.Int) *big.Int {
	var tmp *big.Int

	var err error

	for {
		tmp, err = rand.Int(rand.Reader, f.primeNumber)
		if err != nil || tmp.Cmp(zero) == 0 {
			continue
		}

		break
	}

	return x.Set(tmp)
}

// order returns the size of the field
func (f field) order() *big.Int {
	return f.primeNumber
}

// bitLen of prime order.
func (f field) bitLen() int {
	return f.primeNumber.BitLen()
}

// areEqual returns whether both elements are equal.
func (f field) areEqual(x, y *big.Int) bool {
	return f.isZero(f.sub(new(big.Int), x, y))
}

// isZero true if x == 0; false else
func (f field) isZero(x *big.Int) bool {
	return x.Sign() == 0
}

// // isSquare returns whether the big.Int is a quadratic square.
// func (f field) isSquare(x *big.Int) bool {
// 	// x^((p-1)/2) == 1
// 	return f.areEqual(f.exponent(new(big.Int), x, f.pMinus1Div2), f.one(new(big.Int)))
// }

func (f field) isEqualPrime(f2 *field) bool {
	return f.primeNumber.Cmp(f2.primeNumber) == 0
}

func (f field) mod(x *big.Int) *big.Int {
	return x.Mod(x, f.primeNumber)
}

// neg sets x to -y, returns x
func (f field) neg(x, y *big.Int) *big.Int {
	return f.mod(x.Neg(y))
}

// add sets x to y + z, returns x
func (f field) add(x, y, z *big.Int) *big.Int {
	return f.mod(x.Add(y, z))
}

// sub sets x to y - z, returns x
func (f field) sub(x, y, z *big.Int) *big.Int {
	return f.mod(x.Sub(y, z))
}

// mul sets x to y * z, returns x
func (f field) mul(x, y, z *big.Int) *big.Int {
	return f.mod(x.Mul(y, z))
}

// square sets x to y ^ 2, returns x
func (f field) square(x, y *big.Int) *big.Int {
	return f.mod(x.Mul(y, y))
}

// inv sets x to y^(p-2), returns x
func (f field) inv(x, y *big.Int) *big.Int {
	return f.exponent(x, y, f.pMinus2)
}

// exponent sets x yo y^z, returns x
func (f field) exponent(x, y, z *big.Int) *big.Int {
	return x.Exp(y, z, f.primeNumber)
}

// cmov sets x to z if cond = true; y else; returns x
func (f field) cmov(x, y, z *big.Int, cond bool) *big.Int {
	if cond {
		x.Set(z)
	} else {
		x.Set(y)
	}

	return x
}

func (f field) sgn0(x *big.Int) int {
	return int(x.Bit(0))
}

// sqrt3mod4 sets x to y^((p + 1) / 4)
func (f field) sqrt3mod4(x, y *big.Int) *big.Int {
	return f.exponent(x, y, f.exp)
}

// sqrt shortcut of sqrt3mod4
func (f field) sqrt(x, y *big.Int) *big.Int {
	return f.sqrt3mod4(x, y)
}

// func (f field) copy() *field {
// 	p, _ := new(big.Int).SetString(f.primeNumber.Text(10), 10)
// 	fc := newField(p)
// 	return fc
// }
