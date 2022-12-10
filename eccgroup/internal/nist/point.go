// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package nist

// nistECGenericPoint is generic interface for nistec.P224Point, nistec.P256Point, nistec.P384Point and nistec.P521Point.
type nistECGenericPoint[point any] interface {
	// Add sets q = p1 + p2, and returns q. The points may overlap.
	Add(p1, p2 point) point
	// Bytes returns the uncompressed or infinity encoding of p, as specified in SEC 1, Version 2.0, Section 2.3.3.
	// Note that the encoding of the point at infinity is shorter than all other encodings.
	Bytes() []byte
	// BytesCompressed returns the compressed or infinity encoding of p, as specified in SEC 1, Version 2.0, Section 2.3.3.
	// Note that the encoding of the point at infinity is shorter than all other encodings.
	BytesCompressed() []byte
	// Double sets q = p + p, and returns q. The points may overlap.
	Double(p point) point
	// ScalarBaseMult sets p = scalar * B, where B is the canonical generator, and returns p.
	ScalarBaseMult(scalar []byte) (point, error)
	// ScalarMult sets p = scalar * q, and returns p.
	ScalarMult(p point, scalar []byte) (point, error)
	// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
	Select(p1, p2 point, cond int) point
	// Set sets p = q and returns p.
	Set(p point) point
	// SetBytes sets p to the compressed, uncompressed, or infinity value encoded in b, as specified in SEC 1, Version 2.0, Section 2.3.4.
	// If the point is not on the curve, it returns nil and an error, and the receiver is unchanged. Otherwise, it returns p.
	SetBytes(b []byte) (point, error)
	// SetGenerator sets p to the canonical generator and returns p.
	SetGenerator() point
}
