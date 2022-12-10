// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Report reports an error if got is different from want.
func Report(tb testing.TB, got, want interface{}, inputs ...interface{}) {
	tb.Helper()

	builder := &strings.Builder{}
	fmt.Fprintf(builder, "\n") //nolint:revive //no need check err

	for i, in := range inputs {
		fmt.Fprintf(builder, "input[%v]: %v\n", i, in) //nolint:revive //no need check err
	}

	fmt.Fprintf(builder, "got:  %v\nwant: %v\n", got, want) //nolint:revive //no need check err
	tb.Helper()
	tb.Fatalf(builder.String())
}

// CheckOk fails the test if result == false.
func CheckOk(tb testing.TB, result bool, msg string) { //nolint:revive //necessary for functionality
	tb.Helper()

	if !result {
		tb.Fatal(msg)
	}
}

// checkErr fails on error condition. mustFail indicates whether err is expected
// to be nil or not.
func checkErr(tb testing.TB, err error, mustFail bool, msg string) { //nolint:revive //necessary for functionality
	tb.Helper()

	if err != nil && !mustFail {
		tb.Fatalf("msg: %v\nerr: %v", msg, err)
	}

	if err == nil && mustFail {
		tb.Fatalf("msg: %v\nerr: %v", msg, err)
	}
}

// CheckNoErr fails if err !=nil. Print msg as an error message.
func CheckNoErr(tb testing.TB, err error, msg string) { tb.Helper(); checkErr(tb, err, false, msg) }

// CheckIsErr fails if err ==nil. Print msg as an error message.
func CheckIsErr(tb testing.TB, err error, msg string) { tb.Helper(); checkErr(tb, err, true, msg) }

// CheckPanic returns true if call to function 'f' caused panic.
func CheckPanic(f func()) error {
	hasPanicked := errors.New("no panic detected")

	defer func() {
		if r := recover(); r == nil {
			hasPanicked = nil
		}
	}()
	f()

	return hasPanicked
}
