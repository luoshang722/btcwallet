// Copyright (c) 2016 The btcsuite developers
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package wallet

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// TODO: The transaction store and address manager need to be updated together,
// but each operate under different namespaces and are changed under new
// transactions.  This is not error safe as we lose transaction semantics.
//
// I'm unsure of the best way to solve this.  Some possible solutions and
// drawbacks:
//
//   1. Open write transactions here and pass the handle to every waddrmr and
//      wtxmgr method.  This complicates the caller code everywhere, however.
//
//   2. Move the wtxmgr namespace into the waddrmgr namespace, likely under its
//      own bucket.  This entire function can then be moved into the waddrmgr
//      package, which updates the nested wtxmgr.  This removes some of
//      separation between the components.
//
//   3. Use multiple wtxmgrs, one for each account, nested in the waddrmgr
//      namespace.  This still provides some sort of logical separation
//      (transaction handling remains in another package, and is simply used by
//      waddrmgr), but may result in duplicate transactions being saved if they
//      are relevant to multiple accounts.
//
//   4. Store wtxmgr-related details under the waddrmgr namespace, but solve the
//      drawback of #3 by splitting wtxmgr to save entire transaction records
//      globally for all accounts, with credit/debit/balance tracking per
//      account.  Each account would also save the relevant transaction hashes
//      and block incidence so the full transaction can be loaded from the
//      waddrmgr transactions bucket.  This currently seems like the best
//      solution.

// ProcessAttachedBlock processes a new block attached to the main chain.
//
// TODO: Eventually this function will require the entire block header so it may
// be saved to the database.  This is a requirement for SPV.
func (w *Wallet) ProcessAttachedBlock(block *wtxmgr.BlockMeta, relevantTxs []*wtxmgr.TxRecord) error {
	// TODO: All database operations in this function must be done under a
	// single transaction.

	err := w.Manager.SetSyncedTo(&waddrmgr.BlockStamp{
		Height: block.Height,
		Hash:   block.Hash,
	})
	if err != nil {
		return err
	}
	for i := range relevantTxs {
		err = w.insertTransaction(relevantTxs[i], block)
		if err != nil {
			return err
		}
	}

	// Notify interested clients of the connected block.
	w.NtfnServer.notifyAttachedBlock(block)

	// Send notification of mined or unmined transaction to any interested
	// clients.
	//
	// TODO: This should be done together with the above notification so the
	// notification server does not need to combine them for the newer
	// notification API.
	for i := range relevantTxs {
		details, err := w.TxStore.UniqueTxDetails(&relevantTxs[i].Hash,
			&block.Block)
		if err != nil {
			log.Errorf("Cannot query transaction details for "+
				"notifiation: %v", err)
		} else {
			w.NtfnServer.notifyMinedTransaction(details, block)
		}
	}

	return nil
}

func (w *Wallet) insertTransaction(rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta) error {
	err := w.TxStore.InsertTx(rec, block)
	if err != nil {
		return err
	}

	// Check every output to determine whether it is controlled by a wallet
	// key.  If so, mark the output as a credit.
	for i, output := range rec.MsgTx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript,
			w.chainParams)
		if err != nil {
			// Non-standard outputs are skipped.
			continue
		}
		for _, addr := range addrs {
			ma, err := w.Manager.Address(addr)
			if err == nil {
				// TODO: Credits should be added with the
				// account they belong to, so wtxmgr is able to
				// track per-account balances.
				err = w.TxStore.AddCredit(rec, block, uint32(i),
					ma.Internal())
				if err != nil {
					return err
				}
				err = w.Manager.MarkUsed(addr)

				if err != nil {
					return err
				}
				log.Debugf("Marked address %v used", addr)
				continue
			}

			// Missing addresses are skipped.  Other errors should
			// be propagated.
			if !waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
				return err
			}
		}
	}

	return nil
}

// ProcessDetachedBlock processes a block removed from the main chain during a
// reorg.  Detached blocks must be processed before the attached blocks on the
// new main chain.
//
// TODO: It would be better to process all attached and detached blocks together
// during a reorganize.
func (w *Wallet) ProcessDetachedBlock(blockHeight int32, blockHash *wire.ShaHash) error {
	// TODO: All database operations in this function must be done under a
	// single transaction.

	// TODO: Detached blocks ahead of the current sync point should be
	// ignored, or return an error informing the syncer that the blocks
	// inbetween are needed as well.  Without this, it is possible for
	// reorgs during initial sync to cause the entire wallet to become
	// desynced and will require a full rescan.

	// Disconnect the last seen block from the manager if it matches the
	// removed block.
	iter := w.Manager.NewIterateRecentBlocks()
	if iter != nil && iter.BlockStamp().Hash == *blockHash {
		if iter.Prev() {
			prev := iter.BlockStamp()
			w.Manager.SetSyncedTo(&prev)
			err := w.TxStore.Rollback(prev.Height + 1)
			if err != nil {
				return err
			}
		} else {
			// The reorg is farther back than the recently-seen list
			// of blocks has recorded, so set it to unsynced which
			// will in turn lead to a rescan from either the
			// earliest blockstamp the addresses in the manager are
			// known to have been created.
			w.Manager.SetSyncedTo(nil)
			// Rollback everything but the genesis block.
			err := w.TxStore.Rollback(1)
			if err != nil {
				return err
			}
		}
	}

	// Notify interested clients of the disconnected block.
	w.NtfnServer.notifyDetachedBlock(blockHash)

	return nil
}

// ProcessUnminedTransaction adds the unmined transaction described by rec to
// the wallet.
func (w *Wallet) ProcessUnminedTransaction(rec *wtxmgr.TxRecord) error {
	// TODO: All database operations in this function must be done under a
	// single transaction.

	err := w.insertTransaction(rec, nil)
	if err != nil {
		return err
	}

	details, err := w.TxStore.UniqueTxDetails(&rec.Hash, nil)
	if err != nil {
		log.Errorf("Cannot query transaction details for notification: %v", err)
	} else {
		w.NtfnServer.notifyUnminedTransaction(details)
	}

	return nil
}

// RescanResult describes a mined transaction discovered through a rescan.
type RescanResult struct {
	Transaction *wtxmgr.TxRecord
	Block       *wtxmgr.BlockMeta
}

func (w *Wallet) ProcessRescanResults(results []RescanResult, rescannedThrough *wtxmgr.Block) error {
	// TODO: All database operations in this function must be done under a
	// single transaction.

	for _, result := range results {
		err := w.insertTransaction(result.Transaction, result.Block)
		if err != nil {
			return err
		}
	}

	// TODO: There needs to be a way to only mark particular data as
	// unsynced.  Currently this conflicts with
	return w.Manager.SetSyncedTo(&waddrmgr.BlockStamp{
		Hash:   rescannedThrough.Hash,
		Height: rescannedThrough.Height,
	})
}
