// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package dleq

import (
	"encoding"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/cymony/cryptomony/eccgroup"
)

// Proof represents generated proofs
type Proof interface {
	// BinaryMarshaler returns a byte representation of proof.
	encoding.BinaryMarshaler
	// BinaryUnmarshaler recovers an proof from a byte representation produced by encoding.BinaryMarshaler.
	encoding.BinaryUnmarshaler

	// TextMarshaler returns a base64 standard string encoding of the proof.
	encoding.TextMarshaler

	// TextUnmarshaler sets the base64 standard string encoding of the proof produced by encoding.TextMarshaler
	encoding.TextUnmarshaler
}

type prf struct {
	s, c *eccgroup.Scalar
	g    eccgroup.Group
}

func newProof(g eccgroup.Group, s, c *eccgroup.Scalar) Proof {
	return &prf{
		g: g,
		s: s,
		c: c,
	}
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (p *prf) MarshalBinary() ([]byte, error) {
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

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (p *prf) UnmarshalBinary(data []byte) error {
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

// MarshalText implements the encoding.TextMarshaler interface.
func (p *prf) MarshalText() (text []byte, err error) {
	b, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (p *prf) UnmarshalText(text []byte) error {
	sb, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("proof unmarshalText err: %w", err)
	}

	return p.UnmarshalBinary(sb)
}
