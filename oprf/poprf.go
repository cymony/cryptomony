// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package oprf

import (
	"crypto/subtle"

	"github.com/cymony/cryptomony/eccgroup"
)

// PartialObliviousClient is oprf client instance with mode ModePOPRF
type PartialObliviousClient struct {
	sPubKey    *PublicKey
	tweakedKey *eccgroup.Element
	client
}

// NewPartialObliviousClient returns new instance of oprf client with mode ModePOPRF
func NewPartialObliviousClient(s Suite, sPub *PublicKey) (*PartialObliviousClient, error) {
	if !isSuiteAvailable(s) {
		return nil, ErrInvalidSuite
	}

	if sPub == nil {
		return nil, ErrEmptyKey
	}

	return &PartialObliviousClient{client: client{s, ModePOPRF}, sPubKey: sPub}, nil
}

// Blind function blinding given inputs, returns FinalizeData for Finaliza function and EvaluationRequest to send server
func (c *PartialObliviousClient) Blind(inputs [][]byte, info []byte) (*FinalizeData, *EvaluationRequest, error) {
	if len(inputs) == 0 {
		return nil, nil, ErrInputValidation
	}

	blinds, blindedElements, tweakedKey, err := blindPOPRF(c.client, c.sPubKey.e, inputs, info)
	if err != nil {
		return nil, nil, err
	}

	c.tweakedKey = tweakedKey

	evalReq := &EvaluationRequest{
		BlindedElements: blindedElements,
	}
	finData := &FinalizeData{
		Inputs:      inputs,
		Blinds:      blinds,
		EvalRequest: evalReq,
	}

	return finData, evalReq, nil
}

// DeterministicBlind is doing same thing with Blind but with given blinds
func (c *PartialObliviousClient) DeterministicBlind(inputs [][]byte, blinds []*eccgroup.Scalar, info []byte) (*FinalizeData, *EvaluationRequest, error) {
	if len(inputs) == 0 {
		return nil, nil, ErrInputValidation
	}

	if len(inputs) != len(blinds) {
		return nil, nil, ErrInputValidation
	}

	dst := createHashToScalarDST(c.mode, c.s)
	//nolint:gocritic // it is not commented code
	// framedInfo = "Info" || I2OSP(len(info), 2) || info
	framedInfo := createInfoLabel(info)
	//nolint:gocritic // it is not commented code
	// m = G.HashToScalar(framedInfo)
	m := c.s.Group().HashToScalar(framedInfo, dst)
	//nolint:gocritic // it is not commented code
	// T = G.ScalarBaseMult(m)
	T := c.s.Group().NewElement().Base().Multiply(m)
	//nolint:gocritic // it is not commented code
	// tweakedKey = T + pkS
	tweakedKey := c.s.Group().NewElement().Set(T).Add(c.sPubKey.e)
	if tweakedKey.IsIdentity() {
		return nil, nil, ErrInvalidInput
	}

	c.tweakedKey = tweakedKey

	blindedEls, err := c.client.blind(inputs, blinds)
	if err != nil {
		return nil, nil, err
	}

	evalReq := &EvaluationRequest{
		BlindedElements: blindedEls,
	}
	finData := &FinalizeData{
		Inputs:      inputs,
		Blinds:      blinds,
		EvalRequest: evalReq,
	}

	return finData, evalReq, nil
}

// Finalize function implements the final step of POPRF evaluation
func (c *PartialObliviousClient) Finalize(finData *FinalizeData, evalRes *EvaluationResponse, info []byte) ([][]byte, error) {
	if err := c.client.validate(finData, evalRes); err != nil {
		return nil, err
	}

	return finalizePOPRF(c.client, finData.Blinds, finData.Inputs, info, c.tweakedKey, evalRes.EvaluatedElements, finData.EvalRequest.BlindedElements, evalRes.Proof)
}

// PartialObliviousServer is oprf server instance with mode ModePOPRF
type PartialObliviousServer struct {
	server
}

// NewPartialObliviousServer returns new instance of oprf server with mode ModePOPRF
func NewPartialObliviousServer(s Suite, privKey *PrivateKey) (*PartialObliviousServer, error) {
	if !isSuiteAvailable(s) {
		return nil, ErrInvalidSuite
	}

	if privKey == nil {
		return nil, ErrEmptyKey
	}

	return &PartialObliviousServer{server: server{s: s, mode: ModePOPRF, privKey: privKey}}, nil
}

// BlindEvaluate evaluates blinded elements
func (s *PartialObliviousServer) BlindEvaluate(evalReq *EvaluationRequest, info []byte) (*EvaluationResponse, error) {
	if evalReq == nil || len(evalReq.BlindedElements) == 0 {
		return nil, ErrInputValidation
	}

	evaluatedElements, proof, err := blindEvaluatePOPRF(s.server, evalReq.BlindedElements, info)
	if err != nil {
		return nil, err
	}

	return &EvaluationResponse{
		EvaluatedElements: evaluatedElements,
		Proof:             proof,
	}, nil
}

// FinalEvaluate is generating expected finalize output
func (s *PartialObliviousServer) FinalEvaluate(input, info []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrInputValidation
	}

	return evaluatePOPRF(s.server, input, info)
}

// VerifyFinalize verifies finalize output is expected or not
func (s *PartialObliviousServer) VerifyFinalize(input, info, exptectedOutput []byte) bool {
	gotOut, err := s.FinalEvaluate(input, info)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(gotOut, exptectedOutput) == 1
}

func blindPOPRF(c client, pkS *eccgroup.Element, inputs [][]byte, info []byte) (blinds []*eccgroup.Scalar, blindedEls []*eccgroup.Element, tweakKey *eccgroup.Element, err error) {
	dst := createHashToScalarDST(c.mode, c.s)
	//nolint:gocritic // it is not commented code
	// framedInfo = "Info" || I2OSP(len(info), 2) || info
	framedInfo := createInfoLabel(info)
	//nolint:gocritic // it is not commented code
	// m = G.HashToScalar(framedInfo)
	m := c.s.Group().HashToScalar(framedInfo, dst)
	//nolint:gocritic // it is not commented code
	// T = G.ScalarBaseMult(m)
	T := c.s.Group().NewElement().Base().Multiply(m)
	//nolint:gocritic // it is not commented code
	// tweakedKey = T + pkS
	tweakedKey := c.s.Group().NewElement().Set(T).Add(pkS)
	if tweakedKey.IsIdentity() {
		return nil, nil, nil, ErrInvalidInput
	}

	blinds, blindedElements, err := blindOPRF(c, inputs)
	if err != nil {
		return nil, nil, nil, err
	}

	return blinds, blindedElements, tweakedKey, nil
}

func blindEvaluatePOPRF(s server, blindedElements []*eccgroup.Element, info []byte) ([]*eccgroup.Element, []byte, error) {
	dst := createHashToScalarDST(s.mode, s.s)
	//nolint:gocritic // it is not commented code
	// framedInfo = "Info" || I2OSP(len(info), 2) || info
	framedInfo := createInfoLabel(info)
	//nolint:gocritic // it is not commented code
	// m = G.HashToScalar(framedInfo)
	m := s.s.Group().HashToScalar(framedInfo, dst)
	// t = skS + m
	t := s.s.Group().NewScalar().Set(s.privKey.k).Add(m)
	// if t == 0: raise InverseError
	if t.IsZero() {
		return nil, nil, errInverse
	}

	evaluatedElements := make([]*eccgroup.Element, len(blindedElements))

	for i := range blindedElements {
		//nolint:gocritic // it is not commented code
		// evaluatedElement = G.ScalarInverse(t) * blindedElement
		invT := s.s.Group().NewScalar().Set(t).Invert()
		evaluatedElement := s.s.Group().NewElement().Set(blindedElements[i]).Multiply(invT)
		evaluatedElements[i] = evaluatedElement
	}
	//nolint:gocritic // it is not commented code
	// tweakedKey = G.ScalarBaseMult(t)
	tweakedKey := s.s.Group().NewElement().Base().Multiply(t)

	//nolint:gocritic // it is not commented code
	// proof = GenerateProof(t, G.Generator(), tweakedKey, evaluatedElements, blindedElements)
	proof, err := produceProof(s.s.Group(), s.mode, s.s, t, s.s.Group().Base(), tweakedKey, evaluatedElements, blindedElements, nil)
	if err != nil {
		return nil, nil, err
	}

	return evaluatedElements, proof, nil
}

func finalizePOPRF(c client, blinds []*eccgroup.Scalar, inputs [][]byte, info []byte, tweakedKey *eccgroup.Element, evaluatedElements, blindedElements []*eccgroup.Element, proof []byte) ([][]byte, error) {
	// if VerifyProof(G.Generator(), tweakedKey, evaluatedElements, blindedElements, proof) == false: raise VerifyError
	if err := produceVerify(c.s.Group(), c.mode, c.s, c.s.Group().Base(), tweakedKey, evaluatedElements, blindedElements, proof); err != nil {
		return nil, err
	}

	outputs := make([][]byte, len(inputs))

	for i := range inputs {
		//nolint:gocritic // it is not commented code
		// N = G.ScalarInverse(blind) * evaluatedElement
		invBlind := c.s.Group().NewScalar().Set(blinds[i]).Invert()
		N := c.s.Group().NewElement().Set(evaluatedElements[i]).Multiply(invBlind)
		//nolint:gocritic // it is not commented code
		// unblindedElement = G.SerializeElement(N)
		unblindedElement := N.Encode()

		//nolint:gocritic // it is not commented code
		// hashInput = I2OSP(len(input), 2) || input || I2OSP(len(info), 2) || info || I2OSP(len(unblindedElement), 2) || unblindedElement || "Finalize"
		// return Hash(hashInput)
		hashResult, err := produceHashResult(c.s.Hash(), inputs[i], info, unblindedElement)
		if err != nil {
			return nil, err
		}

		outputs[i] = hashResult
	}

	return outputs, nil
}

func evaluatePOPRF(s server, input, info []byte) ([]byte, error) {
	h2gDST := createHashToGroupDST(s.mode, s.s)
	//nolint:gocritic // it is not commented code
	// inputElement = G.HashToGroup(input)
	inputElement := s.s.Group().HashToGroup(input, h2gDST)
	if inputElement.IsIdentity() {
		return nil, ErrInvalidInput
	}

	h2sDST := createHashToScalarDST(s.mode, s.s)
	//nolint:gocritic // it is not commented code
	// framedInfo = "Info" || I2OSP(len(info), 2) || info
	framedInfo := createInfoLabel(info)
	//nolint:gocritic // it is not commented code
	// m = G.HashToScalar(framedInfo)
	m := s.s.Group().HashToScalar(framedInfo, h2sDST)
	// t = skS + m
	t := s.s.Group().NewScalar().Set(s.privKey.k).Add(m)
	// if t == 0: raise InverseError
	if t.IsZero() {
		return nil, errInverse
	}

	//nolint:gocritic // it is not commented code
	// evaluatedElement = G.ScalarInverse(t) * inputElement
	invT := s.s.Group().NewScalar().Set(t).Invert()
	evaluatedElement := s.s.Group().NewElement().Set(inputElement).Multiply(invT)

	//nolint:gocritic // it is not commented code
	// issuedElement = G.SerializeElement(evaluatedElement)
	issuedElement := evaluatedElement.Encode()

	hashResult, err := produceHashResult(s.s.Hash(), input, info, issuedElement)
	if err != nil {
		return nil, err
	}

	return hashResult, nil
}
