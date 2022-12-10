// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package dleq

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/internal/test"
)

func TestDLEQ(t *testing.T) {
	for _, group := range []eccgroup.Group{
		eccgroup.Ristretto255Sha512,
		eccgroup.P256Sha256,
		eccgroup.P384Sha384,
		eccgroup.P521Sha512,
	} {
		t.Run(fmt.Sprintf("Test For Group: %s", group.String()), func(t *testing.T) {
			conf := &Configuration{
				Group: group,
				DST:   []byte("my_domain_separation_tag"),
			}

			cy, err := NewProver(conf)
			test.CheckNoErr(t, err, "should not error returned while new prover creating")
			mony, err := NewVerifier(conf)
			test.CheckNoErr(t, err, "should not error returned while new verifier creating")

			k := group.RandomScalar()
			A := group.RandomElement()
			B := group.NewElement().Add(A).Multiply(k)
			C := group.RandomElement()
			D := group.NewElement().Add(C).Multiply(k)

			proof, err := cy.GenerateProof(k, A, B, []*eccgroup.Element{C}, []*eccgroup.Element{D})
			test.CheckNoErr(t, err, "should not error returned while generating proof")
			isVerified := mony.VerifyProof(A, B, []*eccgroup.Element{C}, []*eccgroup.Element{D}, proof)
			if !isVerified {
				test.Report(t, isVerified, true, fmt.Sprintf("using group %s, dleq is not verified", group.String()))
			}

			testMarshalBinary(t, proof)
			testMarshalText(t, proof)
		})
	}
}

func testMarshalBinary(t *testing.T, proof Proof) {
	t.Helper()

	p := proof.(*prf) //nolint:errcheck //no need check err

	wantBytes, err := proof.MarshalBinary()
	test.CheckNoErr(t, err, "should not error returned while marshaling proof")

	gotProof := newProof(p.g, p.s, p.c)
	err = gotProof.UnmarshalBinary(wantBytes)
	test.CheckNoErr(t, err, "should not error returned while unmarshaling proof")

	gotBytes, err := gotProof.MarshalBinary()
	test.CheckNoErr(t, err, "should not error returned while marshaling proof")

	if !bytes.Equal(gotBytes, wantBytes) {
		test.Report(t, gotBytes, wantBytes, fmt.Sprintf("Group: %s", p.g.String()))
	}
}

func testMarshalText(t *testing.T, proof Proof) {
	t.Helper()

	p := proof.(*prf) //nolint:errcheck //no need check err

	wantText, err := proof.MarshalText()
	test.CheckNoErr(t, err, "should not error returned while marshaling proof")

	gotProof := newProof(p.g, p.s, p.c)
	err = gotProof.UnmarshalText(wantText)
	test.CheckNoErr(t, err, "should not error returned while unmarshaling proof")

	gotText, err := gotProof.MarshalText()
	test.CheckNoErr(t, err, "should not error returned while marshaling proof")

	if !bytes.Equal(gotText, wantText) {
		test.Report(t, gotText, wantText, fmt.Sprintf("Group: %s", p.g.String()))
	}
}

func TestErrors(t *testing.T) {
	t.Run("Proof Unmarshal Error", func(t *testing.T) {
		p := new(prf)
		p.g = eccgroup.P256Sha256
		dummyBytesShort := make([]byte, 2)
		err := p.UnmarshalBinary(dummyBytesShort)
		if !errors.Is(err, io.ErrShortBuffer) {
			test.Report(t, err, io.ErrShortBuffer, "different unmarshal error")
		}
	})
}

func BenchmarkDLEQ(b *testing.B) {
	g := eccgroup.P256Sha256
	conf := &Configuration{[]byte("my_domain_separation_tag"), g}
	Peggy, err := NewProver(conf)
	test.CheckNoErr(b, err, "should not error returned while new prover creating")
	Victor, err := NewVerifier(conf)
	test.CheckNoErr(b, err, "should not error returned while new verifier creating")

	k := g.RandomScalar()
	A := g.Base()
	kA := g.NewElement().Add(A).Multiply(k)

	B := g.RandomElement()
	kB := g.NewElement().Add(B).Multiply(k)

	proof, err := Peggy.GenerateProof(k, A, kA, []*eccgroup.Element{B}, []*eccgroup.Element{kB})
	test.CheckNoErr(b, err, "should not error returned while generating proof")

	b.Run("GenerateProof", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Peggy.GenerateProof(k, A, kA, []*eccgroup.Element{B}, []*eccgroup.Element{kB}) //nolint:errcheck //benchmark
		}
	})
	b.Run("VerifyProof", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = Victor.VerifyProof(A, kA, []*eccgroup.Element{B}, []*eccgroup.Element{kB}, proof)
		}
	})
}
