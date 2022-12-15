// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dleq

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/internal/test"
)

var allGroups = []eccgroup.Group{
	eccgroup.Ristretto255Sha512,
	eccgroup.P256Sha256,
	eccgroup.P384Sha384,
	eccgroup.P521Sha512,
}
var dst = []byte("my_domain_separation_tag_for_test")

func TestDLEQ(t *testing.T) {
	for _, group := range allGroups {
		t.Run(fmt.Sprintf("Group/%s", group.String()), func(t *testing.T) {
			conf := &Configuration{
				Group: group,
				DST:   dst,
			}

			cy, err := NewProver(conf)
			test.CheckNoErr(t, err, "new prover err")

			mony, err := NewVerifier(conf)
			test.CheckNoErr(t, err, "new verifier err")

			k := group.RandomScalar()

			A := group.RandomElement()
			B := group.NewElement().Add(A).Multiply(k)

			C := group.RandomElement()
			D := group.NewElement().Add(C).Multiply(k)

			proof, err := cy.GenerateProof(k, A, B, []*eccgroup.Element{C}, []*eccgroup.Element{D})
			test.CheckNoErr(t, err, "generate proof err")

			isVerified := mony.VerifyProof(A, B, []*eccgroup.Element{C}, []*eccgroup.Element{D}, proof)
			if !isVerified {
				test.Report(t, isVerified, true, fmt.Sprintf("using group %s, dleq is not verified", group.String()))
			}
		})
	}
}

func TestWithRandomness(t *testing.T) {
	for _, group := range allGroups {
		t.Run(fmt.Sprintf("Group/%s", group.String()), func(t *testing.T) {
			conf := &Configuration{dst, group}

			prover, err := NewProver(conf)
			test.CheckNoErr(t, err, "new prover err")

			rnd := group.RandomScalar()
			k := group.RandomScalar()

			A := group.RandomElement()
			B := group.NewElement().Add(A).Multiply(k)

			C := group.RandomElement()
			D := group.NewElement().Add(C).Multiply(k)

			proofOne, err := prover.GenerateProofWithRandomness(k, A, B, []*eccgroup.Element{C}, []*eccgroup.Element{D}, rnd)
			test.CheckNoErr(t, err, "generate proof err")

			proofTwo, err := prover.GenerateProofWithRandomness(k, A, B, []*eccgroup.Element{C}, []*eccgroup.Element{D}, rnd)
			test.CheckNoErr(t, err, "generate proof err")

			if !bytes.Equal(proofOne, proofTwo) {
				test.Report(t, "not equal", "equal", proofOne, proofTwo)
			}
		})
	}
}

func BenchmarkDLEQ(b *testing.B) {
	for _, group := range allGroups {
		conf := &Configuration{dst, group}

		Peggy, err := NewProver(conf)
		test.CheckNoErr(b, err, "new prover err")

		Victor, err := NewVerifier(conf)
		test.CheckNoErr(b, err, "new verifier err")

		rnd := group.RandomScalar()
		k := group.RandomScalar()

		A := group.RandomElement()
		kA := group.NewElement().Add(A).Multiply(k)

		B := group.RandomElement()
		kB := group.NewElement().Add(B).Multiply(k)

		b.Run(fmt.Sprintf("%s/GenerateProof", group.String()), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = Peggy.GenerateProof(k, A, kA, []*eccgroup.Element{B}, []*eccgroup.Element{kB}) //nolint:errcheck //benchmark
			}
		})

		b.Run(fmt.Sprintf("%s/GenerateProofWithRandomness", group.String()), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = Peggy.GenerateProofWithRandomness(k, A, kA, []*eccgroup.Element{B}, []*eccgroup.Element{kB}, rnd) //nolint:errcheck //benchmark
			}
		})

		proof, err := Peggy.GenerateProof(k, A, kA, []*eccgroup.Element{B}, []*eccgroup.Element{kB})
		test.CheckNoErr(b, err, "generate proof err")

		b.Run(fmt.Sprintf("%s/VerifyProof", group.String()), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = Victor.VerifyProof(A, kA, []*eccgroup.Element{B}, []*eccgroup.Element{kB}, proof)
			}
		})
	}
}
