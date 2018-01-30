// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spv

import "github.com/btcsuite/btclog"

var log = btclog.Disabled

// UseLogger uses a specified Logger to output package logging info.
func UseLogger(logger btclog.Logger) {
	log = logger
}
