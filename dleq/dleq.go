// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

/*
Package dleq implements Discrete Logarithm Equivalence Proofs.

ContextString must be given as DST from upper protocol (e.g. VOPRF, POPRF)

Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-discrete-logarithm-equivale
*/
package dleq

import (
	"math/big"

	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/hash"
	"github.com/cymony/cryptomony/utils"
)

var (
	labelSeed         = "Seed-"
	labelComposite    = "Composite"
	labelHashToScalar = "HashToScalar-"
	labelChallenge    = "Challenge"
)

// Configuration struct for DLEQ algorithm
type Configuration struct {
	DST   []byte         // Domain separation tag
	Group eccgroup.Group // prime-order elliptic curve group
}

type dlq struct {
	c    *Configuration
	hash hash.Hashing
}

func newDleq(c *Configuration) (*dlq, error) {
	var d dlq

	switch c.Group.String() {
	case eccgroup.P256Sha256.String():
		d.hash = hash.SHA256
	case eccgroup.P384Sha384.String():
		d.hash = hash.SHA384
	case eccgroup.P521Sha512.String():
		d.hash = hash.SHA512
	case eccgroup.Ristretto255Sha512.String():
		d.hash = hash.SHA512
	default:
		return nil, ErrUnsupportedGroup
	}

	d.c = c

	return &d, nil
}

func (dl *dlq) GenerateProof(k *eccgroup.Scalar, a, b *eccgroup.Element, c, d []*eccgroup.Element) ([]byte, error) {
	return dl.generateProof(k, a, b, c, d, nil)
}

func (dl *dlq) GenerateProofWithRandomness(k *eccgroup.Scalar, a, b *eccgroup.Element, c, d []*eccgroup.Element, rnd *eccgroup.Scalar) ([]byte, error) {
	return dl.generateProof(k, a, b, c, d, rnd)
}

// See https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-14.html#name-proof-generation
func (dl *dlq) generateProof(k *eccgroup.Scalar, a, b *eccgroup.Element, c, d []*eccgroup.Element, rnd *eccgroup.Scalar) ([]byte, error) {
	M, Z, err := dl.computeComposites(k, b, c, d)
	if err != nil {
		return nil, err
	}

	var r *eccgroup.Scalar
	//nolint:gocritic //not a commented code
	// r = G.RandomScalar()
	if rnd == nil {
		r = dl.c.Group.NewScalar().Random()
	} else {
		r = rnd
	}

	// t2 = r * A
	t2 := dl.c.Group.NewElement().Add(a).Multiply(r)
	// t3 = r * M
	t3 := dl.c.Group.NewElement().Add(M).Multiply(r)

	//nolint:gocritic //not a commented code
	// Bm = G.SerializeElement(B)
	Bm := b.Encode()

	//nolint:gocritic //not a commented code
	// a0 = G.SerializeElement(M)
	a0 := M.Encode()

	//nolint:gocritic //not a commented code
	// a1 = G.SerializeElement(Z)
	a1 := Z.Encode()

	//nolint:gocritic //not a commented code
	// a2 = G.SerializeElement(t2)
	a2 := t2.Encode()

	//nolint:gocritic //not a commented code
	// a3 = G.SerializeElement(t3)
	a3 := t3.Encode()

	//nolint:gocritic //not a commented code
	// I2OSP(len(Bm), 2)
	bmI2Osp2, err := utils.I2osp(big.NewInt(int64(len(Bm))), 2)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// I2OSP(len(a0), 2)
	a0I2Osp2, err := utils.I2osp(big.NewInt(int64(len(a0))), 2)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// I2OSP(len(a1), 2)
	a1I2Osp2, err := utils.I2osp(big.NewInt(int64(len(a1))), 2)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// I2OSP(len(a2), 2)
	a2I2Osp2, err := utils.I2osp(big.NewInt(int64(len(a2))), 2)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// I2OSP(len(a3), 2)
	a3I2Osp2, err := utils.I2osp(big.NewInt(int64(len(a3))), 2)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// h2Input = I2OSP(len(Bm), 2) || Bm ||
	// I2OSP(len(a0), 2) || a0 ||
	// I2OSP(len(a1), 2) || a1 ||
	// I2OSP(len(a2), 2) || a2 ||
	// I2OSP(len(a3), 2) || a3 ||
	// "Challenge"
	h2Input := utils.Concat(bmI2Osp2, Bm, a0I2Osp2, a0, a1I2Osp2, a1, a2I2Osp2, a2, a3I2Osp2, a3, []byte(labelChallenge))

	hashToScalarDST := utils.Concat([]byte(labelHashToScalar), dl.c.DST)

	//nolint:gocritic //not a commented code
	// c = G.HashToScalar(h2Input)
	cc := dl.c.Group.HashToScalar(h2Input, hashToScalarDST)

	// s = (r - c * k) mod G.Order()
	s := dl.c.Group.NewScalar().Add(r).Subtract(dl.c.Group.NewScalar().Add(k).Multiply(cc))

	prf := newProof(dl.c.Group, s, cc)

	return prf.marshalBinary()
}

func (dl *dlq) VerifyProof(a, b *eccgroup.Element, c, d []*eccgroup.Element, proof []byte) bool {
	M, Z, err := dl.computeComposites(nil, b, c, d)
	if err != nil {
		panic(err)
	}

	p := &prf{g: dl.c.Group}

	err = p.unmarshalBinary(proof)
	if err != nil {
		panic(err)
	}

	pB, err := p.marshalBinary()
	if err != nil {
		panic(err)
	}

	cc := dl.c.Group.NewScalar()

	err = cc.UnmarshalBinary(pB[:dl.c.Group.ScalarLength()])
	if err != nil {
		panic(err)
	}

	s := dl.c.Group.NewScalar()

	err = s.UnmarshalBinary(pB[dl.c.Group.ScalarLength() : 2*dl.c.Group.ScalarLength()])
	if err != nil {
		panic(err)
	}

	//nolint:gocritic //not a commented code
	// t2 = ((s * A) + (c * B))
	sA := dl.c.Group.NewElement().Add(a).Multiply(s)
	cB := dl.c.Group.NewElement().Add(b).Multiply(cc)
	t2 := dl.c.Group.NewElement().Add(sA).Add(cB)

	//nolint:gocritic //not a commented code
	// t3 = ((s * M) + (c * Z))
	sM := dl.c.Group.NewElement().Add(M).Multiply(s)
	cZ := dl.c.Group.NewElement().Add(Z).Multiply(cc)
	t3 := dl.c.Group.NewElement().Add(sM).Add(cZ)

	Bm := b.Encode()
	a0 := M.Encode()
	a1 := Z.Encode()
	a2 := t2.Encode()
	a3 := t3.Encode()

	//nolint:gocritic //not a commented code
	// I2OSP(len(Bm), 2)
	bmI2Osp2, err := utils.I2osp(big.NewInt(int64(len(Bm))), 2)
	if err != nil {
		panic(err)
	}

	//nolint:gocritic //not a commented code
	// I2OSP(len(a0), 2)
	a0I2Osp2, err := utils.I2osp(big.NewInt(int64(len(a0))), 2)
	if err != nil {
		panic(err)
	}

	//nolint:gocritic //not a commented code
	// I2OSP(len(a1), 2)
	a1I2Osp2, err := utils.I2osp(big.NewInt(int64(len(a1))), 2)
	if err != nil {
		panic(err)
	}

	//nolint:gocritic //not a commented code
	// I2OSP(len(a2), 2)
	a2I2Osp2, err := utils.I2osp(big.NewInt(int64(len(a2))), 2)
	if err != nil {
		panic(err)
	}

	//nolint:gocritic //not a commented code
	// I2OSP(len(a3), 2)
	a3I2Osp2, err := utils.I2osp(big.NewInt(int64(len(a3))), 2)
	if err != nil {
		panic(err)
	}

	//nolint:gocritic //not a commented code
	// h2Input = I2OSP(len(Bm), 2) || Bm ||
	// 	I2OSP(len(a0), 2) || a0 ||
	// 	I2OSP(len(a1), 2) || a1 ||
	// 	I2OSP(len(a2), 2) || a2 ||
	// 	I2OSP(len(a3), 2) || a3 ||
	// 	"Challenge"
	h2Input := utils.Concat(bmI2Osp2, Bm, a0I2Osp2, a0, a1I2Osp2, a1, a2I2Osp2, a2, a3I2Osp2, a3, []byte(labelChallenge))

	hashToScalarDST := utils.Concat([]byte(labelHashToScalar), dl.c.DST)

	//nolint:gocritic //not a commented code
	// expectedC = G.HashToScalar(h2Input)
	expectedC := dl.c.Group.HashToScalar(h2Input, hashToScalarDST)

	return expectedC.Equal(cc) == 1
}

func (dl *dlq) computeComposites(k *eccgroup.Scalar, b *eccgroup.Element, c, d []*eccgroup.Element) (*eccgroup.Element, *eccgroup.Element, error) {
	//nolint:gocritic //not a commented code
	// Bm = G.SerializeElement(B)
	Bm := b.Encode()

	// seedDST = "Seed-" || contextString -- (contextString given from upper protocol as DST)
	seedDST := utils.Concat([]byte(labelSeed), dl.c.DST)

	//nolint:gocritic //not a commented code
	// h1Input = I2OSP(len(Bm), 2) || Bm || I2OSP(len(seedDST), 2) || seedDST
	// seed = Hash(h1Input)
	lenBmI2osp2, err := utils.I2osp(big.NewInt(int64((len(Bm)))), 2)
	if err != nil {
		return nil, nil, err
	}

	lenSeedDSTI2osp2, err := utils.I2osp(big.NewInt(int64(len(seedDST))), 2)
	if err != nil {
		return nil, nil, err
	}

	H := dl.hash.New()

	err = H.MustWriteAll(lenBmI2osp2, Bm, lenSeedDSTI2osp2, seedDST)
	if err != nil {
		return nil, nil, err
	}

	seed := make([]byte, H.OutputSize())

	err = H.MustReadFull(seed)
	if err != nil {
		return nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// I2OSP(len(seed), 2) // used in for
	lenSeedI2osp2, err := utils.I2osp(big.NewInt(int64(len(seed))), 2)
	if err != nil {
		return nil, nil, err
	}

	hashToScalarDST := utils.Concat([]byte(labelHashToScalar), dl.c.DST)

	//nolint:gocritic //not a commented code
	// M = G.Identity()
	M := dl.c.Group.NewElement().Identity()

	//nolint:gocritic //not a commented code
	// Z = G.Identity() // used if k is not nil
	Z := dl.c.Group.NewElement().Identity()

	//nolint:gocritic //not a commented code
	// for i in range(m):
	for i := range c {
		//   Ci = G.SerializeElement(C[i])
		Ci := c[i].Encode()
		//   Di = G.SerializeElement(D[i])
		Di := d[i].Encode()

		// I2OSP(i, 2)
		iI2osp2, err := utils.I2osp(big.NewInt(int64(i)), 2)
		if err != nil {
			return nil, nil, err
		}

		// I2OSP(len(Ci), 2)
		ciI2osp2, err := utils.I2osp(big.NewInt(int64(len(Ci))), 2)
		if err != nil {
			return nil, nil, err
		}

		// I2OSP(len(Di), 2)
		diI2osp2, err := utils.I2osp(big.NewInt(int64(len(Di))), 2)
		if err != nil {
			return nil, nil, err
		}

		//   h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) || I2OSP(len(Ci), 2) || Ci || I2OSP(len(Di), 2) || Di || "Composite"
		h2Input := utils.Concat(lenSeedI2osp2, seed, iI2osp2, ciI2osp2, Ci, diI2osp2, Di, []byte(labelComposite))

		// di = G.HashToScalar(h2Input)
		di := dl.c.Group.HashToScalar(h2Input, hashToScalarDST)

		//   M = di * C[i] + M
		diCi := dl.c.Group.NewElement()
		diCi.Add(c[i])
		diCi.Multiply(di)
		M.Add(diCi)

		if k == nil {
			// Z = di * D[i] + Z
			diDi := dl.c.Group.NewElement()
			diDi.Add(d[i])
			diDi.Multiply(di)
			Z.Add(diDi)
		}
	}

	if k != nil {
		// Z = k * M
		Z = dl.c.Group.NewElement()
		Z.Add(M)
		Z.Multiply(k)
	}

	// return (M, Z)
	return M, Z, nil
}
