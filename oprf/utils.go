// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package oprf

import (
	"math/big"

	"github.com/cymony/cryptomony/dleq"
	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/hash"
	"github.com/cymony/cryptomony/utils"
)

func produceProof(g eccgroup.Group, mode ModeType, s Suite, k *eccgroup.Scalar, a, b *eccgroup.Element, c, d []*eccgroup.Element, rnd *eccgroup.Scalar) ([]byte, error) {
	cnf := &dleq.Configuration{
		Group: g,
		DST:   createContextString(mode, s),
	}

	prover, err := dleq.NewProver(cnf)
	if err != nil {
		return nil, err
	}

	var proof []byte
	if rnd == nil {
		proof, err = prover.GenerateProof(k, a, b, c, d)
		if err != nil {
			return nil, err
		}
	} else {
		proof, err = prover.GenerateProofWithRandomness(k, a, b, c, d, rnd)
		if err != nil {
			return nil, err
		}
	}

	return proof, nil
}

// produceVerify returns non-nil error if verification failed, and nil otherwise.
func produceVerify(g eccgroup.Group, mode ModeType, s Suite, a, b *eccgroup.Element, c, d []*eccgroup.Element, proof []byte) error {
	cnf := &dleq.Configuration{
		Group: g,
		DST:   createContextString(mode, s),
	}

	verifier, err := dleq.NewVerifier(cnf)
	if err != nil {
		return err
	}

	if !verifier.VerifyProof(a, b, c, d, proof) {
		return ErrVerify
	}

	return nil
}

func produceUnblind(g eccgroup.Group, blind *eccgroup.Scalar, evaluatedElement *eccgroup.Element) []byte {
	//nolint:gocritic // it is not commented code
	// N = G.ScalarInverse(blind) * evaluatedElement
	invBlind := g.NewScalar().Set(blind).Invert()
	N := g.NewElement().Set(evaluatedElement).Multiply(invBlind)

	//nolint:gocritic // it is not commented code
	// unblindedElement = G.SerializeElement(N)
	unblindedElement := N.Encode()

	return unblindedElement
}

func produceHashResult(h hash.Hashing, inputs ...[]byte) ([]byte, error) {
	hashInput, err := produceHashInput(inputs...)
	if err != nil {
		return nil, err
	}

	H := h.New()
	H.Reset()

	if err := H.MustWriteAll(hashInput); err != nil {
		return nil, err
	}

	out := make([]byte, H.OutputSize())
	if err := H.MustReadFull(out); err != nil {
		return nil, err
	}

	return H.Sum(nil), nil
}

func produceHashInput(inputs ...[]byte) ([]byte, error) {
	var hashInput []byte
	//nolint:gocritic // it is not commented code
	// hashInput = I2OSP(len(input), 2) || input || I2OSP(len(el), 2) || el || "Finalize"
	for _, in := range inputs {
		i2ospLenIn2, err := utils.I2osp(big.NewInt(int64(len(in))), 2)
		if err != nil {
			return nil, err
		}

		hashInput = append(hashInput, i2ospLenIn2...)
		hashInput = append(hashInput, in...)
	}

	hashInput = append(hashInput, createFinalizeLabel()...)

	return hashInput, nil
}
