// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oprf

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"log"
	"testing"

	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/internal/test"
)

type commonClient interface {
	blind(inputs [][]byte, blinds []*eccgroup.Scalar) ([]*eccgroup.Element, error)
	DeterministicBlind(inputs [][]byte, blinds []*eccgroup.Scalar) (*FinalizeData, *EvaluationRequest, error)
	Blind(inputs [][]byte) (*FinalizeData, *EvaluationRequest, error)
	Finalize(d *FinalizeData, e *EvaluationResponse) ([][]byte, error)
}

type c1 struct {
	*PartialObliviousClient
	info []byte
}

func (c *c1) Blind(inputs [][]byte) (*FinalizeData, *EvaluationRequest, error) {
	return c.PartialObliviousClient.Blind(inputs, c.info)
}

func (c *c1) DeterministicBlind(inputs [][]byte, blinds []*eccgroup.Scalar) (*FinalizeData, *EvaluationRequest, error) {
	return c.PartialObliviousClient.DeterministicBlind(inputs, blinds, c.info)
}

func (c *c1) Finalize(f *FinalizeData, e *EvaluationResponse) ([][]byte, error) {
	return c.PartialObliviousClient.Finalize(f, e, c.info)
}

type commonServer interface {
	BlindEvaluate(req *EvaluationRequest) (*EvaluationResponse, error)
	FinalEvaluate(input []byte) ([]byte, error)
	VerifyFinalize(input, expectedOutput []byte) bool
	PublicKey() *PublicKey
}

type s1 struct {
	*PartialObliviousServer
	info []byte
}

func (s *s1) BlindEvaluate(req *EvaluationRequest) (*EvaluationResponse, error) {
	return s.PartialObliviousServer.BlindEvaluate(req, s.info)
}

func (s *s1) FinalEvaluate(input []byte) ([]byte, error) {
	return s.PartialObliviousServer.FinalEvaluate(input, s.info)
}

func (s *s1) VerifyFinalize(input, expectedOutput []byte) bool {
	return s.PartialObliviousServer.VerifyFinalize(input, s.info, expectedOutput)
}

type canMarshal interface {
	encoding.BinaryMarshaler
	UnmarshalBinary(id Suite, data []byte) (err error)
}

func testMarshal(t *testing.T, suite Suite, x, y canMarshal, name string) {
	t.Helper()

	wantBytes, err := x.MarshalBinary()
	test.CheckNoErr(t, err, "error on marshaling "+name)

	err = y.UnmarshalBinary(suite, wantBytes)
	test.CheckNoErr(t, err, "error on unmarshaling "+name)

	gotBytes, err := x.MarshalBinary()
	test.CheckNoErr(t, err, "error on marshaling "+name)

	if !bytes.Equal(gotBytes, wantBytes) {
		test.Report(t, gotBytes, wantBytes)
	}
}

func elementsMarshalBinary(g eccgroup.Group, e []*eccgroup.Element) []byte {
	output := make([]byte, 2, len(e)*int(g.ElementLength()))
	binary.BigEndian.PutUint16(output[0:2], uint16(len(e)))

	for i := range e {
		ei := e[i].Encode()
		output = append(output, ei...)
	}

	return output
}

func testAPI(t *testing.T, server commonServer, client commonClient) {
	t.Helper()

	inputs := [][]byte{{0x00}, {0xFF}}
	finData, evalReq, err := client.Blind(inputs)
	test.CheckNoErr(t, err, "invalid blinding of client")

	blinds := make([]*eccgroup.Scalar, len(finData.Blinds))
	for i := range blinds {
		blinds[i] = finData.Blinds[i].Copy()
	}

	_, detEvalReq, err := client.DeterministicBlind(inputs, blinds)
	test.CheckNoErr(t, err, "invalid deterministic blinding of client")
	test.CheckOk(t, len(detEvalReq.BlindedElements) == len(evalReq.BlindedElements), "invalid number of evaluations")

	for i := range evalReq.BlindedElements {
		test.CheckOk(t, evalReq.BlindedElements[i].Equal(detEvalReq.BlindedElements[i]) == 1, "invalid blinded element mismatch")
	}

	eval, err := server.BlindEvaluate(evalReq)
	test.CheckNoErr(t, err, "invalid evaluation of server")
	test.CheckOk(t, eval != nil, "invalid evaluation of server: no evaluation")

	clientOutputs, err := client.Finalize(finData, eval)
	test.CheckNoErr(t, err, "invalid finalize of client")
	test.CheckOk(t, clientOutputs != nil, "invalid finalize of client: no outputs")

	for i := range inputs {
		valid := server.VerifyFinalize(inputs[i], clientOutputs[i])
		test.CheckOk(t, valid, "invalid verification from the server")

		serverOutput, err := server.FinalEvaluate(inputs[i])
		test.CheckNoErr(t, err, "FullEvaluate failed")

		if !bytes.Equal(serverOutput, clientOutputs[i]) {
			test.Report(t, serverOutput, clientOutputs[i])
		}
	}
}

func TestAPI(t *testing.T) {
	info := []byte("shared info")

	for _, suite := range []Suite{
		SuiteRistretto255Sha512,
		SuiteP256Sha256,
		SuiteP384Sha384,
		SuiteP521Sha512,
	} {
		t.Run(suite.(fmt.Stringer).String(), func(t *testing.T) {
			private, err := GenerateKey(suite)
			test.CheckNoErr(t, err, "failed private key generation")
			testMarshal(t, suite, private, new(PrivateKey), "PrivateKey")
			public := private.Public()
			testMarshal(t, suite, public, new(PublicKey), "PublicKey")

			t.Run("OPRF", func(t *testing.T) {
				s, err := NewServer(suite, private)
				test.CheckNoErr(t, err, "server creation")
				c, err := NewClient(suite)
				test.CheckNoErr(t, err, "client creation")
				testAPI(t, s, c)
			})

			t.Run("VOPRF", func(t *testing.T) {
				s, err := NewVerifiableServer(suite, private)
				test.CheckNoErr(t, err, "server creation")
				c, err := NewVerifiableClient(suite, s.PublicKey())
				test.CheckNoErr(t, err, "client creation")
				testAPI(t, s, c)
			})

			t.Run("POPRF", func(t *testing.T) {
				ss, err := NewPartialObliviousServer(suite, private)
				test.CheckNoErr(t, err, "server creation")
				s := &s1{ss, info}
				cc, err := NewPartialObliviousClient(suite, s.PublicKey())
				test.CheckNoErr(t, err, "client creation")
				c := &c1{cc, info}
				testAPI(t, s, c)
			})
		})
	}
}

func TestErrors(t *testing.T) {
	goodID := SuiteP256Sha256
	strErrNil := "must be nil"
	strErrK := "must fail key"
	strErrC := "must fail client"
	strErrS := "must fail server"

	t.Run("badID", func(t *testing.T) {
		var badID Suite

		k, err := GenerateKey(badID)
		test.CheckIsErr(t, err, strErrK)
		test.CheckOk(t, k == nil, strErrNil)

		k, err = DeriveKey(badID, ModeOPRF, nil, nil)
		test.CheckIsErr(t, err, strErrK)
		test.CheckOk(t, k == nil, strErrNil)

		err = new(PrivateKey).UnmarshalBinary(badID, nil)
		test.CheckIsErr(t, err, strErrK)

		err = new(PublicKey).UnmarshalBinary(badID, nil)
		test.CheckIsErr(t, err, strErrK)

		_, err = NewClient(badID)
		test.CheckIsErr(t, err, strErrC)

		_, err = NewServer(badID, nil)
		test.CheckIsErr(t, err, strErrS)

		_, err = NewVerifiableClient(badID, nil)
		test.CheckIsErr(t, err, strErrC)

		_, err = NewVerifiableServer(badID, nil)
		test.CheckIsErr(t, err, strErrS)

		_, err = NewPartialObliviousClient(badID, nil)
		test.CheckIsErr(t, err, strErrC)

		_, err = NewPartialObliviousServer(badID, nil)
		test.CheckIsErr(t, err, strErrS)
	})

	t.Run("nilPubKey", func(t *testing.T) {
		_, err := NewVerifiableClient(goodID, nil)
		test.CheckIsErr(t, err, strErrC)
		_, err = NewPartialObliviousClient(goodID, nil)
		test.CheckIsErr(t, err, strErrS)
	})

	t.Run("nilCalls", func(t *testing.T) {
		c, err := NewClient(goodID)
		test.CheckNoErr(t, err, "client creation")
		finData, evalReq, err := c.Blind(nil)
		test.CheckIsErr(t, err, strErrC)
		test.CheckOk(t, finData == nil, strErrNil)
		test.CheckOk(t, evalReq == nil, strErrNil)

		var emptyEval EvaluationResponse
		finData, _, err = c.Blind([][]byte{[]byte("in0"), []byte("in1")})
		test.CheckNoErr(t, err, "blind err")

		out, err := c.Finalize(finData, &emptyEval)
		test.CheckIsErr(t, err, strErrC)
		test.CheckOk(t, out == nil, strErrNil)
	})

	t.Run("invalidProof", func(t *testing.T) {
		key, err := GenerateKey(goodID)
		test.CheckNoErr(t, err, "generate key err")

		s, err := NewVerifiableServer(goodID, key)
		test.CheckNoErr(t, err, "client creation")
		c, err := NewVerifiableClient(goodID, key.Public())
		test.CheckNoErr(t, err, "server creation")

		finData, evalReq, err := c.Blind([][]byte{[]byte("in0"), []byte("in1")})
		test.CheckNoErr(t, err, "blind err")

		_, err = s.BlindEvaluate(evalReq)
		test.CheckNoErr(t, err, "blind evaluate err")

		_, evalReq, err = c.Blind([][]byte{[]byte("in0"), []byte("in2")})
		test.CheckNoErr(t, err, "blind err")

		badEV, err := s.BlindEvaluate(evalReq)
		test.CheckNoErr(t, err, "blind evaluate err")

		_, err = c.Finalize(finData, badEV)
		test.CheckIsErr(t, err, strErrC)
	})

	t.Run("badKeyGen", func(t *testing.T) {
		key, err := DeriveKey(goodID, ModeType(8), nil, nil)
		test.CheckIsErr(t, err, strErrK)
		test.CheckOk(t, key == nil, strErrNil)
	})
}

func TestKeyMarshals(t *testing.T) {
	priv, err := GenerateKey(SuiteRistretto255Sha512)
	test.CheckNoErr(t, err, "generate key error")

	binPriv, err := priv.MarshalBinary()
	test.CheckNoErr(t, err, "priv binary marshal err")

	err = priv.UnmarshalBinary(SuiteRistretto255Sha512, binPriv)
	test.CheckNoErr(t, err, "priv binary unmarshal err")

	textPriv, err := priv.MarshalText()
	test.CheckNoErr(t, err, "priv text marshal err")

	err = priv.UnmarshalText(SuiteRistretto255Sha512, textPriv)
	test.CheckNoErr(t, err, "priv text unmarshal err")

	pub := priv.Public()

	binPub, err := pub.MarshalBinary()
	test.CheckNoErr(t, err, "pub binary marshal err")

	err = pub.UnmarshalBinary(SuiteRistretto255Sha512, binPub)
	test.CheckNoErr(t, err, "pub binary unmarshal err")

	textPub, err := pub.MarshalText()
	test.CheckNoErr(t, err, "pub text marshal err")

	err = pub.UnmarshalText(SuiteRistretto255Sha512, textPub)
	test.CheckNoErr(t, err, "pub text unmarshal err")
}

func Example_oprf() {
	suite := SuiteP256Sha256
	//   Server(sk, pk, info*)
	private, err := GenerateKey(suite)
	if err != nil {
		log.Fatalln(err)
	}

	server, err := NewServer(suite, private)
	if err != nil {
		log.Fatalln(err)
	}

	//   Client(info*)
	client, err := NewClient(suite)
	if err != nil {
		log.Fatalln(err)
	}
	//   =================================================================
	//   finData, evalReq = Blind(input)
	inputs := [][]byte{[]byte("first input"), []byte("second input")}

	finData, evalReq, err := client.Blind(inputs)
	if err != nil {
		log.Fatalln(err)
	}
	//
	//                               evalReq
	//                             ---------->
	//
	//                               evaluation = Evaluate(evalReq, info*)
	evaluation, err := server.BlindEvaluate(evalReq)
	if err != nil {
		log.Fatalln(err)
	}
	//
	//                              evaluation
	//                             <----------
	//
	//   output = Finalize(finData, evaluation, info*)
	outputs, err := client.Finalize(finData, evaluation)
	fmt.Print(err == nil && len(inputs) == len(outputs))
	// Output: true
}

func BenchmarkAPI(b *testing.B) {
	for _, suite := range []Suite{
		SuiteRistretto255Sha512,
		SuiteP256Sha256,
		SuiteP384Sha384,
		SuiteP521Sha512,
	} {
		key, err := GenerateKey(suite)
		test.CheckNoErr(b, err, "failed key generation")

		b.Run("OPRF/"+suite.String(), func(b *testing.B) {
			s, _ := NewServer(suite, key) //nolint:errcheck // benchmark
			c, _ := NewClient(suite)      //nolint:errcheck // benchmark
			benchAPI(b, s, c)
		})

		b.Run("VOPRF/"+suite.String(), func(b *testing.B) {
			s, _ := NewVerifiableServer(suite, key)           //nolint:errcheck // benchmark
			c, _ := NewVerifiableClient(suite, s.PublicKey()) //nolint:errcheck // benchmark
			benchAPI(b, s, c)
		})

		b.Run("POPRF/"+suite.String(), func(b *testing.B) {
			info := []byte("shared info")
			ss, _ := NewPartialObliviousServer(suite, key)            //nolint:errcheck // benchmark
			cc, _ := NewPartialObliviousClient(suite, ss.PublicKey()) //nolint:errcheck // benchmark

			s := &s1{ss, info}
			c := &c1{cc, info}
			benchAPI(b, s, c)
		})
	}
}

func benchAPI(b *testing.B, server commonServer, client commonClient) {
	b.Helper()

	inputs := [][]byte{[]byte("first input"), []byte("second input")}
	finData, evalReq, err := client.Blind(inputs)
	test.CheckNoErr(b, err, "failed client request")

	eval, err := server.BlindEvaluate(evalReq)
	test.CheckNoErr(b, err, "failed server evaluate")

	clientOutputs, err := client.Finalize(finData, eval)
	test.CheckNoErr(b, err, "failed client finalize")

	b.Run("Client/Request", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = client.Blind(inputs) //nolint:errcheck // benchmark
		}
	})

	b.Run("Server/Evaluate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = server.BlindEvaluate(evalReq) //nolint:errcheck // benchmark
		}
	})

	b.Run("Client/Finalize", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = client.Finalize(finData, eval) //nolint:errcheck // benchmark
		}
	})

	b.Run("Server/VerifyFinalize", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := range inputs {
				server.VerifyFinalize(inputs[j], clientOutputs[j])
			}
		}
	})

	b.Run("Server/FullEvaluate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := range inputs {
				_, _ = server.FinalEvaluate(inputs[j]) //nolint:errcheck // benchmark
			}
		}
	})
}
