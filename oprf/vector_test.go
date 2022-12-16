// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//nolint:govet,gocritic // it is test struct
package oprf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/internal/test"
)

type vector struct {
	ID       int      `json:"suiteID"`
	Name     string   `json:"suiteName"`
	Mode     ModeType `json:"mode"`
	Hash     string   `json:"hash"`
	PkSm     string   `json:"pkSm"`
	SkSm     string   `json:"skSm"`
	Seed     string   `json:"seed"`
	KeyInfo  string   `json:"keyInfo"`
	GroupDST string   `json:"groupDST"`
	Vectors  []struct {
		Batch             int    `json:"Batch"`
		Blind             string `json:"Blind"`
		Info              string `json:"Info"`
		BlindedElement    string `json:"BlindedElement"`
		EvaluationElement string `json:"EvaluationElement"`
		Proof             struct {
			Proof string `json:"proof"`
			R     string `json:"r"`
		} `json:"Proof"`
		Input  string `json:"Input"`
		Output string `json:"Output"`
	} `json:"vectors"`
}

func toBytes(t *testing.T, s, errMsg string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	test.CheckNoErr(t, err, "decoding "+errMsg)

	return b
}

func toListBytes(t *testing.T, s, errMsg string) [][]byte {
	t.Helper()

	strs := strings.Split(s, ",")

	out := make([][]byte, len(strs))
	for i := range strs {
		out[i] = toBytes(t, strs[i], errMsg)
	}

	return out
}

func flattenList(t *testing.T, s, errMsg string) []byte {
	t.Helper()

	strs := strings.Split(s, ",")
	out := []byte{0, 0}
	binary.BigEndian.PutUint16(out, uint16(len(strs)))

	for i := range strs {
		out = append(out, toBytes(t, strs[i], errMsg)...)
	}

	return out
}

func toScalar(t *testing.T, g eccgroup.Group, s, errMsg string) *eccgroup.Scalar {
	t.Helper()

	r := g.NewScalar()
	rBytes := toBytes(t, s, errMsg)
	err := r.UnmarshalBinary(rBytes)
	test.CheckNoErr(t, err, errMsg)

	return r
}

func readFile(t *testing.T, fileName string) []vector {
	t.Helper()

	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()

	input, err := io.ReadAll(jsonFile)
	if err != nil {
		t.Fatalf("File %v can not be read. Error: %v", fileName, err)
	}

	var v []vector

	err = json.Unmarshal(input, &v)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}

	return v
}

func getSuite(id int) (Suite, error) {
	switch id {
	case SuiteRistretto255Sha512.SuiteID():
		return SuiteRistretto255Sha512, nil
	case SuiteP256Sha256.SuiteID():
		return SuiteP256Sha256, nil
	case SuiteP384Sha384.SuiteID():
		return SuiteP384Sha384, nil
	case SuiteP521Sha512.SuiteID():
		return SuiteP521Sha512, nil
	default:
		return nil, ErrInvalidSuite
	}
}

func getSecretAndTweakedKeyFromInfo(g eccgroup.Group, mode ModeType, s Suite, privKey *PrivateKey, info []byte) (*eccgroup.Scalar, *eccgroup.Element, error) {
	dst := createHashToScalarDST(mode, s)

	// framedInfo = "Info" || I2OSP(len(info), 2) || info
	framedInfo := createInfoLabel(info)
	// m = G.HashToScalar(framedInfo)
	m := g.HashToScalar(framedInfo, dst)
	// t = skS + m
	t := g.NewScalar().Set(privKey.k).Add(m)
	// if t == 0: raise InverseError
	if t.IsZero() {
		return nil, nil, errInverse
	}

	tweakedKey := g.NewElement().Base().Multiply(t)

	return t, tweakedKey, nil
}

func (v *vector) SetUpParties(t *testing.T) (id Suite, s commonServer, c commonClient) {
	t.Helper()

	suiteInterface, err := getSuite(v.ID)
	test.CheckNoErr(t, err, "suite id")
	seed := toBytes(t, v.Seed, "seed for key derivation")
	keyInfo := toBytes(t, v.KeyInfo, "info for key derivation")
	privateKey, err := DeriveKey(suiteInterface, v.Mode, seed, keyInfo)
	test.CheckNoErr(t, err, "deriving key")

	got, err := privateKey.MarshalBinary()
	test.CheckNoErr(t, err, "serializing private key")
	want := toBytes(t, v.SkSm, "private key")
	v.compareBytes(t, got, want)

	var sw commonServer

	var cl commonClient

	var swErr, clErr error

	switch v.Mode {
	case ModeOPRF:
		sw, swErr = NewServer(suiteInterface, privateKey)
		cl, clErr = NewClient(suiteInterface)
	case ModeVOPRF:
		sw, swErr = NewVerifiableServer(suiteInterface, privateKey)
		cl, clErr = NewVerifiableClient(suiteInterface, sw.PublicKey())
	case ModePOPRF:
		var info []byte

		ss, swwErr := NewPartialObliviousServer(suiteInterface, privateKey)
		cc, cllErr := NewPartialObliviousClient(suiteInterface, ss.PublicKey())

		swErr = swwErr
		clErr = cllErr

		sw = &s1{ss, info}
		cl = &c1{cc, info}
	}

	test.CheckNoErr(t, swErr, "server creation")
	test.CheckNoErr(t, clErr, "client creation")

	return suiteInterface, sw, cl
}

func (v *vector) compareLists(t *testing.T, got, want [][]byte) {
	t.Helper()

	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			test.Report(t, got[i], want[i], v.Name, v.Mode, i)
		}
	}
}

func (v *vector) compareBytes(t *testing.T, got, want []byte) {
	t.Helper()

	if !bytes.Equal(got, want) {
		test.Report(t, got, want, v.Name, v.Mode)
	}
}

func (v *vector) test(t *testing.T) {
	params, server, client := v.SetUpParties(t)

	for i, vi := range v.Vectors {
		if v.Mode == ModePOPRF {
			info := toBytes(t, vi.Info, "info")
			ss := server.(*s1) //nolint:errcheck //no need to check err
			cc := client.(*c1) //nolint:errcheck //no need to check err
			ss.info = info
			cc.info = info
		}

		inputs := toListBytes(t, vi.Input, "input")
		blindsBytes := toListBytes(t, vi.Blind, "blind")

		blinds := make([]*eccgroup.Scalar, len(blindsBytes))
		for j := range blindsBytes {
			blinds[j] = params.Group().NewScalar()
			err := blinds[j].UnmarshalBinary(blindsBytes[j])
			test.CheckNoErr(t, err, "invalid blind")
		}

		finData, evalReq, err := client.DeterministicBlind(inputs, blinds)
		test.CheckNoErr(t, err, "invalid blind")

		blindedElementsBytes := elementsMarshalBinary(params.Group(), evalReq.BlindedElements)

		v.compareBytes(t, blindedElementsBytes, flattenList(t, vi.BlindedElement, "blindedElement"))

		eval, err := server.BlindEvaluate(evalReq)
		test.CheckNoErr(t, err, "invalid evaluation")

		elemBytes := elementsMarshalBinary(params.Group(), eval.EvaluatedElements)
		v.compareBytes(t, elemBytes, flattenList(t, vi.EvaluationElement, "evaluation"))

		if v.Mode == ModeVOPRF || v.Mode == ModePOPRF {
			randomness := toScalar(t, params.Group(), vi.Proof.R, "invalid proof random scalar")

			var proof []byte

			switch v.Mode { //nolint:exhaustive //no need case modeOPRF
			case ModeVOPRF:
				ss := server.(*VerifiableServer) //nolint:errcheck //no need to check err
				proof, err = produceProof(ss.s.Group(),
					ss.mode,
					ss.s,
					ss.privKey.k,
					ss.s.Group().Base(),
					ss.server.PublicKey().e,
					evalReq.BlindedElements,
					eval.EvaluatedElements,
					randomness)
				test.CheckNoErr(t, err, "failed proof generation")
			case ModePOPRF:
				ss := server.(*s1) //nolint:errcheck //no need to check err
				keyProof, tweakedKey, err := getSecretAndTweakedKeyFromInfo(ss.s.Group(), ss.mode, ss.s, ss.server.privKey, ss.info)
				test.CheckNoErr(t, err, "tweaking key producing")
				proof, err = produceProof(params.Group(),
					ModePOPRF,
					ss.s,
					keyProof,
					ss.s.Group().Base(),
					tweakedKey,
					eval.EvaluatedElements,
					evalReq.BlindedElements,
					randomness)
				test.CheckNoErr(t, err, "failed proof generation")
			}

			v.compareBytes(t, proof, toBytes(t, vi.Proof.Proof, "proof"))
		}

		outputs, err := client.Finalize(finData, eval)
		test.CheckNoErr(t, err, "invalid finalize")
		expectedOutputs := toListBytes(t, vi.Output, "output")
		v.compareLists(t,
			outputs,
			expectedOutputs,
		)

		for j := range inputs {
			output, err := server.FinalEvaluate(inputs[j])
			test.CheckNoErr(t, err, "invalid full evaluate")

			got := output
			want := expectedOutputs[j]

			if !bytes.Equal(got, want) {
				test.Report(t, got, want, v.Name, v.Mode, i, j)
			}

			test.CheckOk(t, server.VerifyFinalize(inputs[j], output), "verify finalize")
		}
	}
}

func TestVectors(t *testing.T) {
	// Draft published at https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-10
	// Test vectors at https://github.com/cfrg/draft-irtf-cfrg-voprf
	// Version supported: v10
	v := readFile(t, "testdata/allVectors.json")

	for i := range v {
		suite, err := getSuite(v[i].ID)
		if err != nil {
			t.Logf(v[i].Name + " not supported yet")
			continue
		}

		t.Run(fmt.Sprintf("%v/Mode%v", suite, v[i].Mode), v[i].test)
	}
}
