// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package utils

// Concat concatenates multiple byte slice to one byte slice
func Concat(inputs ...[]byte) []byte {
	var out []byte
	for _, in := range inputs {
		out = append(out, in...)
	}

	return out
}
