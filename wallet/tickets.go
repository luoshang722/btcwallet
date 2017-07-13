// Copyright (c) 2016-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"encoding/hex"
	"time"

	"github.com/decred/bitset"
	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/chain"
	"github.com/decred/dcrwallet/wallet/udb"
	"github.com/decred/dcrwallet/walletdb"
)

// GenerateVoteTx creates a vote transaction for a chosen ticket purchase hash
// using the provided votebits.  The ticket purchase transaction must be stored
// by the wallet.
func (w *Wallet) GenerateVoteTx(blockHash *chainhash.Hash, height int32, ticketHash *chainhash.Hash, voteBits stake.VoteBits) (*wire.MsgTx, error) {
	var vote *wire.MsgTx
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
		ticketPurchase, err := w.StakeMgr.TicketPurchase(dbtx, ticketHash)
		if err != nil {
			return err
		}
		vote, err = createUnsignedVote(ticketHash, ticketPurchase,
			height, blockHash, voteBits, w.subsidyCache, w.chainParams)
		if err != nil {
			return err
		}
		return w.signVote(addrmgrNs, ticketPurchase, vote)
	})
	return vote, err
}

// LiveTicketHashes returns the hashes of live tickets that have been purchased
// by the wallet.
//
// BUG: This does not exclude unspent missed or expired tickets.
func (w *Wallet) LiveTicketHashes(includeImmature bool) ([]chainhash.Hash, error) {
	flags := udb.Tunspent | udb.Tlive
	if includeImmature {
		flags |= udb.Timmature
	}

	var ticketHashes []chainhash.Hash
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		var err error
		ticketHashes, err = w.TxStore.TicketHashes(dbtx, flags)
		return err
	})
	return ticketHashes, err
}

// TicketHashesForVotingAddress returns the hashes of all tickets with voting
// rights delegated to votingAddr.  This function does not return the hashes of
// pruned tickets.
func (w *Wallet) TicketHashesForVotingAddress(votingAddr dcrutil.Address) ([]chainhash.Hash, error) {
	var ticketHashes []chainhash.Hash
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		stakemgrNs := tx.ReadBucket(wstakemgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		var err error
		ticketHashes, err = w.StakeMgr.DumpSStxHashesForAddress(
			stakemgrNs, votingAddr)
		if err != nil {
			return err
		}

		// Exclude the hash if the transaction is not saved too.  No
		// promises of hash order are given (and at time of writing,
		// they are copies of iterators of a Go map in wstakemgr) so
		// when one must be removed, replace it with the last and
		// decrease the len.
		for i := 0; i < len(ticketHashes); {
			if w.TxStore.ExistsTx(txmgrNs, &ticketHashes[i]) {
				i++
				continue
			}

			ticketHashes[i] = ticketHashes[len(ticketHashes)-1]
			ticketHashes = ticketHashes[:len(ticketHashes)-1]
		}

		return nil
	})
	return ticketHashes, err
}

// updateStakePoolInvalidTicket properly updates a previously marked Invalid pool ticket,
// it then creates a new entry in the validly tracked pool ticket db.
func (w *Wallet) updateStakePoolInvalidTicket(stakemgrNs walletdb.ReadWriteBucket, addrmgrNs walletdb.ReadBucket,
	addr dcrutil.Address, ticket *chainhash.Hash, ticketHeight int64) error {
	err := w.StakeMgr.RemoveStakePoolUserInvalTickets(stakemgrNs, addr, ticket)
	if err != nil {
		return err
	}
	poolTicket := &udb.PoolTicket{
		Ticket:       *ticket,
		HeightTicket: uint32(ticketHeight),
		Status:       udb.TSImmatureOrLive,
	}

	return w.StakeMgr.UpdateStakePoolUserTickets(stakemgrNs, addrmgrNs, addr, poolTicket)
}

// AddTicket adds a ticket transaction to the wallet.
func (w *Wallet) AddTicket(ticket *dcrutil.Tx) error {
	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		stakemgrNs := tx.ReadWriteBucket(wstakemgrNamespaceKey)

		// Insert the ticket to be tracked and voted.
		err := w.StakeMgr.InsertSStx(stakemgrNs, ticket)
		if err != nil {
			return err
		}

		if w.stakePoolEnabled {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			// Pluck the ticketaddress to identify the stakepool user.
			pkVersion := ticket.MsgTx().TxOut[0].Version
			pkScript := ticket.MsgTx().TxOut[0].PkScript
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkVersion,
				pkScript, w.ChainParams())
			if err != nil {
				return err
			}

			ticketHash := ticket.MsgTx().TxHash()

			chainClient, err := w.requireChainClient()
			if err != nil {
				return err
			}
			rawTx, err := chainClient.GetRawTransactionVerbose(&ticketHash)
			if err != nil {
				return err
			}

			// Update the pool ticket stake. This will include removing it from the
			// invalid slice and adding a ImmatureOrLive ticket to the valid ones.
			err = w.updateStakePoolInvalidTicket(stakemgrNs, addrmgrNs, addrs[0], &ticketHash, rawTx.BlockHeight)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// RevokeTickets creates and sends revocation transactions for any unrevoked
// missed and expired tickets.  The wallet must be unlocked to generate any
// revocations.
func (w *Wallet) RevokeTickets(chainClient *chain.RPCClient) error {
	var ticketHashes []chainhash.Hash
	var tipHash chainhash.Hash
	var tipHeight int32
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		ns := dbtx.ReadBucket(wtxmgrNamespaceKey)
		var err error
		tipHash, tipHeight = w.TxStore.MainChainTip(ns)
		ticketHashes, err = w.TxStore.TicketHashes(dbtx, udb.Tunspent)
		return err
	})
	if err != nil {
		return err
	}

	ticketHashPtrs := make([]*chainhash.Hash, len(ticketHashes))
	for i := range ticketHashes {
		ticketHashPtrs[i] = &ticketHashes[i]
	}
	expiredFuture := chainClient.ExistsExpiredTicketsAsync(ticketHashPtrs)
	missedFuture := chainClient.ExistsMissedTicketsAsync(ticketHashPtrs)
	expiredBitsHex, err := expiredFuture.Receive()
	if err != nil {
		return err
	}
	missedBitsHex, err := missedFuture.Receive()
	if err != nil {
		return err
	}
	expiredBits, err := hex.DecodeString(expiredBitsHex)
	if err != nil {
		return err
	}
	missedBits, err := hex.DecodeString(missedBitsHex)
	if err != nil {
		return err
	}
	revokableTickets := make([]*chainhash.Hash, 0, len(ticketHashes))
	for i, p := range ticketHashPtrs {
		if bitset.Bytes(expiredBits).Get(i) || bitset.Bytes(missedBits).Get(i) {
			revokableTickets = append(revokableTickets, p)
		}
	}
	feePerKb := w.RelayFee()
	revocations := make([]*wire.MsgTx, 0, len(revokableTickets))
	err = walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		for _, ticketHash := range revokableTickets {
			addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
			txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)
			ticketPurchase, err := w.TxStore.Tx(txmgrNs, ticketHash)
			if err != nil {
				return err
			}
			revocation, err := createUnsignedRevocation(ticketHash,
				ticketPurchase, feePerKb)
			if err != nil {
				return err
			}
			err = w.signRevocation(addrmgrNs, ticketPurchase, revocation)
			if err != nil {
				return err
			}
			revocations = append(revocations, revocation)
		}
		return nil
	})
	if err != nil {
		return err
	}

	for i, revocation := range revocations {
		rec, err := udb.NewTxRecordFromMsgTx(revocation, time.Now())
		if err != nil {
			return err
		}
		err = walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
			err = w.StakeMgr.StoreRevocationInfo(dbtx, revokableTickets[i],
				&rec.Hash, &tipHash, tipHeight)
			if err != nil {
				return err
			}
			// Could be more efficient by avoiding processTransaction, as we
			// know it is a revocation.
			err = w.processTransactionRecord(dbtx, rec, nil, nil)
			if err != nil {
				return err
			}
			_, err = chainClient.SendRawTransaction(revocation, true)
			return err
		})
		if err != nil {
			return err
		}
		log.Infof("Revoked ticket %v with revocation %v", revokableTickets[i],
			&rec.Hash)
	}

	return nil
}
