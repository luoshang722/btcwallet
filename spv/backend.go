// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spv

import (
	"context"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/gcs"
	"github.com/decred/dcrd/gcs/blockcf"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrwallet/errors"
	"github.com/decred/dcrwallet/p2p"
	"github.com/decred/dcrwallet/wallet"
	"golang.org/x/sync/errgroup"
)

var _ wallet.NetworkBackend = (*Syncer)(nil)

func pickAny(*p2p.RemotePeer) bool { return true }

// GetBlocks implements the GetBlocks method of the wallet.NetworkBackend
// interface.
func (s *Syncer) GetBlocks(ctx context.Context, blockHashes []*chainhash.Hash) ([]*wire.MsgBlock, error) {
	rp, err := s.pickRemote(pickAny)
	if err != nil {
		return nil, err
	}

	return rp.GetBlocks(ctx, blockHashes)
}

func getCFilters(ctx context.Context, rp *p2p.RemotePeer, blockHashes []*chainhash.Hash) ([]*gcs.Filter, error) {
	// TODO: this is spammy and would be better implemented with a single
	// request/response.
	filters := make([]*gcs.Filter, len(blockHashes))
	g, gctx := errgroup.WithContext(ctx)
	for i := range blockHashes {
		i := i
		g.Go(func() error {
			f, err := rp.GetCFilter(gctx, blockHashes[i])
			filters[i] = f
			return err
		})
	}
	err := g.Wait()
	if err != nil {
		return nil, err
	}
	return filters, nil
}

// GetCFilters implements the GetCFilters method of the wallet.NetworkBackend
// interface.
func (s *Syncer) GetCFilters(ctx context.Context, blockHashes []*chainhash.Hash) ([]*gcs.Filter, error) {
	rp, err := s.pickRemote(pickAny)
	if err != nil {
		return nil, err
	}

	return getCFilters(ctx, rp, blockHashes)
}

// GetHeaders implements the GetHeaders method of the wallet.NetworkBackend
// interface.
func (s *Syncer) GetHeaders(ctx context.Context, blockLocators []*chainhash.Hash, hashStop *chainhash.Hash) ([]*wire.BlockHeader, error) {
	rp, err := s.pickRemote(pickAny)
	if err != nil {
		return nil, err
	}

	h, err := rp.GetHeaders(ctx, blockLocators, hashStop)
	if err != nil {
		return nil, err
	}
	return h.Headers, nil
}

// LoadTxFilter implements the LoadTxFilter method of the wallet.NetworkBackend
// interface.
func (s *Syncer) LoadTxFilter(ctx context.Context, reload bool, addrs []dcrutil.Address, outpoints []wire.OutPoint) error {
	s.filterMu.Lock()
	if reload || s.rescanFilter == nil {
		s.rescanFilter = wallet.NewRescanFilter(nil, nil)
		s.filterData = s.filterData[:0]
	}
	for _, addr := range addrs {
		pkScript, err := txscript.PayToAddrScript(addr)
		if err == nil {
			s.rescanFilter.AddAddress(addr)
			s.filterData.AddRegularPkScript(pkScript)
		}
	}
	for i := range outpoints {
		s.rescanFilter.AddUnspentOutPoint(&outpoints[i])
		s.filterData.AddOutPoint(&outpoints[i])
	}
	s.filterMu.Unlock()
	return nil
}

// PublishTransaction implements the PublishTransaction method of the
// wallet.NetworkBackend interface.
func (s *Syncer) PublishTransaction(ctx context.Context, tx *wire.MsgTx) error {
	msg := wire.NewMsgInvSizeHint(1)
	txHash := tx.TxHash()
	msg.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &txHash))
	return s.forRemotes(func(rp *p2p.RemotePeer) error {
		rp.InvsSent().Add(txHash)
		return rp.SendMessage(ctx, msg)
	})
}

// Rescan implements the Rescan method of the wallet.NetworkBackend interface.
func (s *Syncer) Rescan(ctx context.Context, blockHashes []chainhash.Hash) ([]*wallet.RescannedBlock, error) {
	rp, err := s.pickRemote(pickAny)
	if err != nil {
		return nil, err
	}

	var possibleMatches []*chainhash.Hash
	for i := range blockHashes {
		blockHash := &blockHashes[i]
		key := blockcf.Key(blockHash)
		f, err := s.wallet.CFilter(blockHash)
		if err != nil {
			return nil, err
		}
		s.filterMu.Lock()
		match := f.MatchAny(key, s.filterData)
		s.filterMu.Unlock()
		if match {
			possibleMatches = append(possibleMatches, blockHash)
		}
	}
	if len(possibleMatches) == 0 {
		return nil, nil
	}
	blocks, err := rp.GetBlocks(ctx, possibleMatches)
	if err != nil {
		return nil, err
	}
	var results []*wallet.RescannedBlock
	for i, b := range blocks {
		matchedTxs := s.rescanBlock(b)
		if len(matchedTxs) != 0 {
			results = append(results, &wallet.RescannedBlock{
				BlockHash:    *possibleMatches[i],
				Transactions: matchedTxs,
			})
		}
	}
	return results, nil
}

// StakeDifficulty implements the StakeDifficulty method of the
// wallet.NetworkBackend interface.
//
// This implementation of the method will always error as the stake difficulty
// is not queryable over wire protocol, and when the next stake difficulty is
// available in a header commitment, the wallet will be able to determine this
// itself without requiring the NetworkBackend.
func (s *Syncer) StakeDifficulty(ctx context.Context) (dcrutil.Amount, error) {
	return 0, errors.E(errors.Invalid, "stake difficulty is not queryable over wire protocol")
}
