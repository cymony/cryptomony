// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package oprf

import "github.com/cymony/cryptomony/eccgroup"

type client struct {
	s    Suite
	mode ModeType
}

func (c client) validate(finData *FinalizeData, evalRes *EvaluationResponse) error {
	if l := len(finData.Blinds); len(finData.EvalRequest.BlindedElements) != l || len(evalRes.EvaluatedElements) != l {
		return ErrInputValidation
	}

	return nil
}

func (c client) blind(inputs [][]byte, blinds []*eccgroup.Scalar) ([]*eccgroup.Element, error) {
	dst := createHashToGroupDST(c.mode, c.s)

	blindedElements := make([]*eccgroup.Element, len(inputs))

	for i := range inputs {
		inputElement := c.s.Group().HashToGroup(inputs[i], dst)

		// if inputElement == G.Identity(): raise InvalidInputError
		if inputElement.IsIdentity() {
			return nil, ErrInvalidInput
		}

		//nolint:gocritic //not a commented code
		// blindedElement = blind * inputElement
		blindedElement := c.s.Group().NewElement().Set(inputElement).Multiply(blinds[i])
		blindedElements[i] = blindedElement
	}

	return blindedElements, nil
}
