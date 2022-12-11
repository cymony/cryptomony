// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package oprf

import (
	"crypto/subtle"

	"github.com/cymony/cryptomony/eccgroup"
)

// VerifiableClient is oprf client instance with mode ModeVOPRF
type VerifiableClient struct {
	sPubKey *PublicKey
	client
}

// NewVerifiableClient returns new instance of oprf client with mode ModeVOPRF
func NewVerifiableClient(s Suite, sPub *PublicKey) (*VerifiableClient, error) {
	if !isSuiteAvailable(s) {
		return nil, ErrInvalidSuite
	}

	if sPub == nil {
		return nil, ErrEmptyKey
	}

	return &VerifiableClient{client: client{s, ModeVOPRF}, sPubKey: sPub}, nil
}

// Blind function blinding given inputs, returns FinalizeData for Finaliza function and EvaluationRequest to send server
func (c *VerifiableClient) Blind(inputs [][]byte) (*FinalizeData, *EvaluationRequest, error) {
	if len(inputs) == 0 {
		return nil, nil, ErrInputValidation
	}

	blinds, blindedElements, err := blindVOPRF(c.client, inputs)
	if err != nil {
		return nil, nil, err
	}

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
func (c *VerifiableClient) DeterministicBlind(inputs [][]byte, blinds []*eccgroup.Scalar) (*FinalizeData, *EvaluationRequest, error) {
	if len(inputs) == 0 {
		return nil, nil, ErrInvalidInput
	}

	if len(inputs) != len(blinds) {
		return nil, nil, ErrInvalidInput
	}

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

// Finalize function implements the final step of VOPRF evaluation
func (c *VerifiableClient) Finalize(finData *FinalizeData, evalRes *EvaluationResponse) ([][]byte, error) {
	if err := c.client.validate(finData, evalRes); err != nil {
		return nil, err
	}

	outputs, err := finalizeVOPRF(c.client, finData.Inputs, finData.Blinds, c.sPubKey.e, finData.EvalRequest.BlindedElements, evalRes.EvaluatedElements, evalRes.Proof)
	if err != nil {
		return nil, err
	}

	return outputs, nil
}

// VerifiableServer is oprf server instance with mode ModeVOPRF
type VerifiableServer struct {
	server
}

// NewVerifiableServer returns new instance of oprf server with mode ModeVOPRF
func NewVerifiableServer(s Suite, privKey *PrivateKey) (*VerifiableServer, error) {
	if !isSuiteAvailable(s) {
		return nil, ErrInvalidSuite
	}

	if privKey == nil {
		return nil, ErrEmptyKey
	}

	return &VerifiableServer{server: server{s: s, mode: ModeVOPRF, privKey: privKey}}, nil
}

// BlindEvaluate evaluates blinded elements
func (s *VerifiableServer) BlindEvaluate(evalReq *EvaluationRequest) (*EvaluationResponse, error) {
	if evalReq == nil || len(evalReq.BlindedElements) == 0 {
		return nil, ErrInputValidation
	}

	evaluatedElements, proof, err := blindEvaluateVOPRF(s.server, evalReq.BlindedElements)
	if err != nil {
		return nil, err
	}

	return &EvaluationResponse{
		EvaluatedElements: evaluatedElements,
		Proof:             proof,
	}, nil
}

// FinalEvaluate is generating expected finalize output
func (s *VerifiableServer) FinalEvaluate(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrInputValidation
	}

	return evaluateVOPRF(s.server, input)
}

// VerifyFinalize verifies finalize output is expected or not
func (s *VerifiableServer) VerifyFinalize(input, exptectedOutput []byte) bool {
	gotOut, err := s.FinalEvaluate(input)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(gotOut, exptectedOutput) == 1
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-voprf-protocol
func blindVOPRF(c client, inputs [][]byte) ([]*eccgroup.Scalar, []*eccgroup.Element, error) {
	return blindOPRF(c, inputs)
}

func blindEvaluateVOPRF(s server, blindedElements []*eccgroup.Element) ([]*eccgroup.Element, []byte, error) {
	evaluatedEls := make([]*eccgroup.Element, len(blindedElements))

	for i := range blindedElements {
		evaluatedElement := blindEvaluateOPRF(s, blindedElements[i])
		evaluatedEls[i] = evaluatedElement
	}

	//nolint:gocritic // it is not commented code
	// proof = GenerateProof(skS, G.Generator(), pkS, blindedElements, evaluatedElements)
	proof, err := produceProof(s.s.Group(), s.mode, s.s, s.privKey.k, s.s.Group().Base(), s.privKey.Public().e, blindedElements, evaluatedEls, nil)
	if err != nil {
		return nil, nil, err
	}

	return evaluatedEls, proof, nil
}

func finalizeVOPRF(c client, inputs [][]byte, blinds []*eccgroup.Scalar, serverPubKey *eccgroup.Element, blindedElements, evaluatedElements []*eccgroup.Element, proof []byte) ([][]byte, error) {
	// if VerifyProof(G.Generator(), pkS, blindedElements, evaluatedElements, proof) == false: raise VerifyError
	if err := produceVerify(c.s.Group(), c.mode, c.s, c.s.Group().Base(), serverPubKey, blindedElements, evaluatedElements, proof); err != nil {
		return nil, err
	}

	outputs := make([][]byte, len(inputs))

	for i := range inputs {
		out, err := finalizeOPRF(c, inputs[i], blinds[i], evaluatedElements[i])
		if err != nil {
			return nil, err
		}

		outputs[i] = out
	}

	return outputs, nil
}

func evaluateVOPRF(s server, input []byte) ([]byte, error) {
	return evaluateOPRF(s, input)
}
