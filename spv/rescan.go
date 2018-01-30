// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spv

import (
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
)

// rescanCheckTransaction is a helper function to rescan both stake and regular
// transactions in a block.  It appends transations that match the filters to
// *matches, while updating the filters to add outpoints for new UTXOs
// controlled by this wallet.
//
// This function may only be called with the filter mutex held.
func (s *Syncer) rescanCheckTransactions(matches *[]*wire.MsgTx, txs []*wire.MsgTx, tree int8) {
	for i, tx := range txs {
		// Keep track of whether the transaction has already been added
		// to the result.  It shouldn't be added twice.
		added := false

		// Coinbases and stakebases are handled specially: all inputs of a
		// coinbase and the first input of a stakebase are skipped over as they
		// do not reference any previous outputs and are not checked.
		inputs := tx.TxIn
		if i == 0 {
			switch {
			case tree == wire.TxTreeRegular:
				goto LoopOutputs
			case tree == wire.TxTreeStake:
				inputs = inputs[1:]
			}
		}

		for _, input := range inputs {
			if !s.rescanFilter.ExistsUnspentOutPoint(&input.PreviousOutPoint) {
				continue
			}
			if !added {
				*matches = append(*matches, tx)
				added = true
			}
		}

	LoopOutputs:
		for i, output := range tx.TxOut {
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				output.Version, output.PkScript,
				s.wallet.ChainParams())
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if !s.rescanFilter.ExistsAddress(a) {
					continue
				}

				op := wire.OutPoint{
					Hash:  tx.TxHash(),
					Index: uint32(i),
					Tree:  tree,
				}
				if !s.rescanFilter.ExistsUnspentOutPoint(&op) {
					s.rescanFilter.AddUnspentOutPoint(&op)
					s.filterData.AddOutPoint(&op)
				}

				if !added {
					*matches = append(*matches, tx)
					added = true
				}
			}
		}
	}
}

// rescanBlock rescans a block for any relevant transactions for the passed
// lookup keys.  Any discovered transactions are returned, and the filter is
// updated for the relevant transactions.
func (s *Syncer) rescanBlock(block *wire.MsgBlock) (matches []*wire.MsgTx) {
	s.filterMu.Lock()
	s.rescanCheckTransactions(&matches, block.STransactions, wire.TxTreeStake)
	s.rescanCheckTransactions(&matches, block.Transactions, wire.TxTreeRegular)
	s.filterMu.Unlock()
	return matches
}
