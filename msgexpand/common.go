// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package msgexpand

// See https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-domain-separation-requireme
func checkDST(dst []byte) error {
	if len(dst) == 0 {
		return ErrZeroLengthDST
	}

	if len(dst) < recommendedDSTLen {
		return ErrRecommendedDSTLen
	}

	return nil
}
