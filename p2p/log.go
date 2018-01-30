// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package p2p

import "github.com/btcsuite/btclog"

var log = btclog.Disabled

// UseLogger sets the package logger, which is btclog.Disabled by default.  This
// should only be called during init before main since access is unsynchronized.
func UseLogger(l btclog.Logger) {
	log = l
}
