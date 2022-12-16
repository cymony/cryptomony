// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package oprf implements the Elliptic Curve Oblivious Pseudorandom Function (EC-OPRF) from
// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-16.html
package oprf

import (
	"crypto/subtle"

	"github.com/cymony/cryptomony/eccgroup"
)

// Client is oprf client instance with mode ModeOPRF
type Client struct {
	client
}

// NewClient returns new instance of oprf client with mode ModeOPRF
func NewClient(s Suite) (*Client, error) {
	if !isSuiteAvailable(s) {
		return nil, ErrInvalidSuite
	}

	return &Client{client: client{s, ModeOPRF}}, nil
}

// Blind function blinding given inputs, returns FinalizeData for Finaliza function and EvaluationRequest to send server
func (c *Client) Blind(inputs [][]byte) (*FinalizeData, *EvaluationRequest, error) {
	if len(inputs) == 0 {
		return nil, nil, ErrInputValidation
	}

	for _, input := range inputs {
		if len(input) == 0 {
			return nil, nil, ErrInputValidation
		}
	}

	blinds, blindedElements, err := blindOPRF(c.client, inputs)
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
func (c *Client) DeterministicBlind(inputs [][]byte, blinds []*eccgroup.Scalar) (*FinalizeData, *EvaluationRequest, error) {
	if len(inputs) == 0 {
		return nil, nil, ErrInputValidation
	}

	for _, input := range inputs {
		if len(input) == 0 {
			return nil, nil, ErrInputValidation
		}
	}

	if len(inputs) != len(blinds) {
		return nil, nil, ErrInputValidation
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

// Finalize function implements the final step of OPRF evaluation
func (c *Client) Finalize(finData *FinalizeData, evalRes *EvaluationResponse) ([][]byte, error) {
	if l := len(finData.Inputs); l == 0 || len(finData.Blinds) != l || len(evalRes.EvaluatedElements) != l {
		return nil, ErrInputValidation
	}

	outputs := make([][]byte, len(finData.Inputs))

	for i := range finData.Inputs {
		out, err := finalizeOPRF(c.client, finData.Inputs[i], finData.Blinds[i], evalRes.EvaluatedElements[i])
		if err != nil {
			return nil, err
		}

		outputs[i] = out
	}

	return outputs, nil
}

// Server is oprf server instance with mode ModeOPRF
type Server struct {
	server
}

// NewServer returns new instance of oprf server with mode ModeOPRF
func NewServer(s Suite, privKey *PrivateKey) (*Server, error) {
	if !isSuiteAvailable(s) {
		return nil, ErrInvalidSuite
	}

	if privKey == nil {
		return nil, ErrEmptyKey
	}

	return &Server{server: server{s: s, mode: ModeOPRF, privKey: privKey}}, nil
}

// BlindEvaluate evaluates blinded elements
func (s *Server) BlindEvaluate(evalReq *EvaluationRequest) (*EvaluationResponse, error) {
	if evalReq == nil || len(evalReq.BlindedElements) == 0 {
		return nil, ErrInputValidation
	}

	evalResponse := &EvaluationResponse{}

	for i := range evalReq.BlindedElements {
		evaluatedElement := blindEvaluateOPRF(s.server, evalReq.BlindedElements[i])
		evalResponse.EvaluatedElements = append(evalResponse.EvaluatedElements, evaluatedElement)
	}

	return evalResponse, nil
}

// FinalEvaluate is generating expected finalize output
func (s *Server) FinalEvaluate(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrInputValidation
	}

	return evaluateOPRF(s.server, input)
}

// VerifyFinalize verifies finalize output is expected or not
func (s *Server) VerifyFinalize(input, exptectedOutput []byte) bool {
	gotOut, err := s.FinalEvaluate(input)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(gotOut, exptectedOutput) == 1
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-oprf-protocol
func blindOPRF(c client, inputs [][]byte) ([]*eccgroup.Scalar, []*eccgroup.Element, error) {
	//nolint:gocritic //it is not commented code
	// blind = G.RandomScalar()
	blinds := make([]*eccgroup.Scalar, len(inputs))

	for i := range inputs {
		blind := c.s.Group().RandomScalar()
		blinds[i] = blind
	}

	blindedElements, err := c.blind(inputs, blinds)
	if err != nil {
		return nil, nil, err
	}

	return blinds, blindedElements, nil
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-oprf-protocol
func blindEvaluateOPRF(s server, blindedElement *eccgroup.Element) *eccgroup.Element {
	evaluatedElement := s.s.Group().NewElement().Set(blindedElement).Multiply(s.privKey.k)
	return evaluatedElement
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-oprf-protocol
func finalizeOPRF(c client, input []byte, blind *eccgroup.Scalar, evaluatedElement *eccgroup.Element) ([]byte, error) {
	//nolint:gocritic //it is not commented code
	// N = G.ScalarInverse(blind) * evaluatedElement
	// unblindedElement = G.SerializeElement(N)
	unblindedElement := produceUnblind(c.s.Group(), blind, evaluatedElement)

	//nolint:gocritic //it is not commented code
	// hashInput = I2OSP(len(input), 2) || input || I2OSP(len(unblindedElement), 2) || unblindedElement || "Finalize"
	hashResult, err := produceHashResult(c.s.Hash(), input, unblindedElement)
	if err != nil {
		return nil, err
	}

	return hashResult, nil
}

func evaluateOPRF(s server, input []byte) ([]byte, error) {
	dst := createHashToGroupDST(s.mode, s.s)
	//nolint:gocritic //it is not commented code
	// inputElement = G.HashToGroup(input)
	inputElement := s.s.Group().HashToGroup(input, dst)
	// if inputElement == G.Identity(): raise InvalidInputError
	if inputElement.IsIdentity() {
		return nil, ErrInvalidInput
	}
	//nolint:gocritic //it is not commented code
	// evaluatedElement = skS * inputElement
	evaluatedElement := s.s.Group().NewElement().Set(inputElement).Multiply(s.privKey.k)
	//nolint:gocritic //it is not commented code
	// issuedElement = G.SerializeElement(evaluatedElement)
	issuedElement := evaluatedElement.Encode()
	//nolint:gocritic //it is not commented code
	// hashInput = I2OSP(len(input), 2) || input || I2OSP(len(issuedElement), 2) || issuedElement || "Finalize"
	hashResult, err := produceHashResult(s.s.Hash(), input, issuedElement)
	if err != nil {
		return nil, err
	}

	return hashResult, nil
}
