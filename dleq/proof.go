// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package dleq

import (
	"io"

	"github.com/cymony/cryptomony/eccgroup"
)

// prf struct represents dleq proof
type prf struct {
	s, c *eccgroup.Scalar
	g    eccgroup.Group
}

// newProof creates a new dleq proof representation
func newProof(g eccgroup.Group, s, c *eccgroup.Scalar) *prf {
	return &prf{
		g: g,
		s: s,
		c: c,
	}
}

// marshalBinary is marshaling proof into byte and returns error if exists
func (p *prf) marshalBinary() ([]byte, error) {
	sSize := p.g.ScalarLength()
	out := make([]byte, int(2*sSize))

	sC, err := p.c.MarshalBinary()
	if err != nil {
		return nil, err
	}

	copy(out, sC)

	sS, err := p.s.MarshalBinary()
	if err != nil {
		return nil, err
	}

	copy(out[sSize:], sS)

	return out, nil
}

// unmarshalBinary is unmarshaling given bytes into the prf struct and returns error if exists
func (p *prf) unmarshalBinary(data []byte) error {
	sSize := p.g.ScalarLength()
	if len(data) < int(2*sSize) {
		return io.ErrShortBuffer
	}

	c := p.g.NewScalar()
	if err := c.UnmarshalBinary(data[:sSize]); err != nil {
		return err
	}

	s := p.g.NewScalar()
	if err := s.UnmarshalBinary(data[sSize:int(2*sSize)]); err != nil {
		return err
	}

	p.c = c
	p.s = s

	return nil
}
