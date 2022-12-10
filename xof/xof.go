// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package xof provides an interface for extendable-output functions
package xof

import (
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
)

// XOF defines the interface to hash functions that support arbitrary-length output
type XOF interface {
	// Write absorbs more data into the XOF's state. It panics if called after Read.
	io.Writer

	// Read reads more output from the XOF. It returns io.EOF if the limit has been reached.
	io.Reader

	// Clone returns a copy of the XOF in its current state.
	Clone() XOF

	// Reset restores the XOF to its initial state and discards all data appended by Write.
	Reset()

	// MustWriteAll writes all inputs into the XOF's state. It panics if called after Read.
	// It return error ErrMismatchLengthWrite if mismatch lengths, io.Writer's errors otherwise
	MustWriteAll(inputs ...[]byte) error

	// MustReadFull reads exactly len(buf) bytes from XOF's state.
	// It returns an error if fewer bytes were read.
	// The error is ErrMismatchLengthRead only if mismatch lengths, io.ReadFull's errors otherwise
	MustReadFull(buff []byte) error

	// String returns string representation of the XOF algorithm.
	String() string
}

// Extendable defines type for XOF functions
type Extendable uint

const (
	SHAKE128 Extendable = 1 + iota
	SHAKE256
	BLAKE2XB
	BLAKE2XS
)

const (
	strSHAKE128 = "SHAKE128"
	strSHAKE256 = "SHAKE256"
	strBLAKE2XB = "BLAKE2XB"
	strBLAKE2XS = "BLAKE2XS"
)

// New returns a new instance for extendable-output function
func (id Extendable) New() XOF {
	switch id {
	case SHAKE128:
		s := sha3.NewShake128()
		return &shake{s, strSHAKE128}
	case SHAKE256:
		s := sha3.NewShake256()
		return &shake{s, strSHAKE256}
	case BLAKE2XB:
		b, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
		if err != nil {
			panic(err)
		}

		return blake2xb{b, strBLAKE2XB}
	case BLAKE2XS:
		b, err := blake2s.NewXOF(blake2s.OutputLengthUnknown, nil)
		if err != nil {
			panic(err)
		}

		return blake2xs{b, strBLAKE2XS}
	default:
		panic("xof: XOF function unavalable")
	}
}

type shake struct {
	sha3.ShakeHash
	str string
}

func (s shake) Clone() XOF { return shake{s.ShakeHash.Clone(), s.str} }

func (s shake) MustWriteAll(inputs ...[]byte) error {
	return mustWriteAll(s.ShakeHash, inputs...)
}

func (s shake) MustReadFull(buf []byte) error {
	return mustReadFull(s.ShakeHash, buf)
}

func (s shake) String() string {
	return s.str
}

type blake2xb struct {
	blake2b.XOF
	str string
}

func (b blake2xb) Clone() XOF { return blake2xb{b.XOF.Clone(), b.str} }

func (b blake2xb) MustWriteAll(inputs ...[]byte) error {
	return mustWriteAll(b.XOF, inputs...)
}

func (b blake2xb) MustReadFull(buf []byte) error {
	return mustReadFull(b.XOF, buf)
}

func (b blake2xb) String() string {
	return b.str
}

type blake2xs struct {
	blake2s.XOF
	str string
}

func (b blake2xs) Clone() XOF { return blake2xs{b.XOF.Clone(), b.str} }

func (b blake2xs) MustWriteAll(inputs ...[]byte) error {
	return mustWriteAll(b.XOF, inputs...)
}

func (b blake2xs) MustReadFull(buf []byte) error {
	return mustReadFull(b.XOF, buf)
}

func (b blake2xs) String() string {
	return b.str
}

func mustWriteAll(w io.Writer, inputs ...[]byte) error {
	for _, in := range inputs {
		n, err := w.Write(in)
		if err != nil {
			return err
		} else if n != len(in) {
			return ErrMismatchLengthWrite
		}
	}

	return nil
}

func mustReadFull(r io.Reader, buf []byte) error {
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return err
	} else if n != len(buf) {
		return ErrMismatchLengthRead
	}

	return nil
}
