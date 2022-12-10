// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package dleq

import "github.com/cymony/cryptomony/eccgroup"

// Prover is an interface to identify party that generates proof
type Prover interface {
	// GenerateProof generates proof with given prime-order curve elements
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-proof-generation
	GenerateProof(k *eccgroup.Scalar, A, B *eccgroup.Element, C, D []*eccgroup.Element) (proof []byte, err error)
	// GenerateProof generates a proof with given prime-order curve elements and randomness
	GenerateProofWithRandomness(k *eccgroup.Scalar, A, B *eccgroup.Element, C, D []*eccgroup.Element, rnd *eccgroup.Scalar) (proof []byte, err error)
}

// NewProver returns Prover instance according to configuration
func NewProver(c *Configuration) (Prover, error) {
	return newDleq(c)
}

// Verifier is an interface to identify party that verify proof
type Verifier interface {
	// VerifyProof verifies the proof with given prime-order curve elements
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-proof-verification
	VerifyProof(A, B *eccgroup.Element, C, D []*eccgroup.Element, proof []byte) bool
}

// NewVerifier returns Verifier instance according to configuration
func NewVerifier(c *Configuration) (Verifier, error) {
	return newDleq(c)
}
