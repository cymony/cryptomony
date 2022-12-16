// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utils

import (
	"crypto/rand"
	"fmt"
)

// RandomBytes returns random bytes of with given length (wrapper for crypto/rand).
func RandomBytes(length int) []byte {
	random := make([]byte, length)
	if _, err := rand.Read(random); err != nil {
		// We can as well not panic and try again in a loop
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	return random
}
