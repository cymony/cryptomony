// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

// Package msgexpand generates arbitrary bytes from an XOF or Hash function.
package msgexpand

type MessageExpand interface {
	// Expand generates a pseudo-random byte string of a determined length by
	// expanding an input string.
	Expand(in, dst []byte, lenInBytes int) (uniform []byte, err error)
}
