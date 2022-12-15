// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utils_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cymony/cryptomony/internal/test"
	"github.com/cymony/cryptomony/utils"
)

func TestConcat(t *testing.T) {
	inputs := []string{
		"Test1",
		"Test 2 separated",
		"This is test input",
	}

	for i, in := range inputs {
		t.Run(fmt.Sprintf("#%d", i+1), func(t *testing.T) {
			sep := strings.Split(in, " ")

			var bytes [][]byte
			for i := 0; i < len(sep); i++ {
				if i+1 == len(sep) {
					bytes = append(bytes, []byte(sep[i]))
				} else {
					bytes = append(bytes, []byte(sep[i]), []byte(" "))
				}
			}

			c := utils.Concat(bytes...)

			got := string(c)
			want := in

			if string(c) != in {
				test.Report(t, got, want)
			}
		})
	}
}
