// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spv

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/decred/dcrd/addrmgr"
	"github.com/decred/dcrd/blockchain"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/gcs"
	"github.com/decred/dcrd/gcs/blockcf"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrwallet/errors"
	"github.com/decred/dcrwallet/p2p"
	"github.com/decred/dcrwallet/wallet"
	"golang.org/x/sync/errgroup"
)

const reqSvcs = wire.SFNodeNetwork | wire.SFNodeCF

// ErrNoRemotePeers describes the error of failing to complete an operating due
// to no connected peers.
var ErrNoRemotePeers = errors.New("no remote peers")

// Syncer implements wallet synchronization services by over the Decred wire
// protocol using Simplified Payment Verification (SPV) with compact filters.
type Syncer struct {
	wallet *wallet.Wallet
	lp     *p2p.LocalPeer

	persistantPeers []string

	remotes   map[string]*p2p.RemotePeer
	reqData   map[chainhash.Hash][]*p2p.RemotePeer
	remotesMu sync.Mutex

	// Data filters
	//
	// TODO: Replace precise rescan filter with wallet db accesses to avoid
	// needing to keep all relevant data in memory.
	rescanFilter *wallet.RescanFilter
	filterData   blockcf.Entries
	filterMu     sync.Mutex

	// Sidechain management
	sidechains  wallet.SidechainForest
	sidechainMu sync.Mutex
}

// NewSyncer creates a Syncer that will sync the wallet using SPV.
func NewSyncer(w *wallet.Wallet, lp *p2p.LocalPeer) *Syncer {
	return &Syncer{
		wallet:  w,
		remotes: make(map[string]*p2p.RemotePeer),
		reqData: make(map[chainhash.Hash][]*p2p.RemotePeer),
		lp:      lp,
	}
}

// SetPersistantPeers sets each peer as a persistant peer and disables DNS
// seeding and peer discovery.
func (s *Syncer) SetPersistantPeers(peers []string) {
	s.persistantPeers = peers
}

var times int

// Run synchronizes the wallet, returning when synchronization fails or the
// context is cancelled.  If startupSync is true, all synchronization tasks
// needed to fully register the wallet for notifications and synchronize it with
// the dcrd server are performed.  Otherwise, it will listen for notifications
// but not register for any updates.
func (s *Syncer) Run(ctx context.Context, startupSync bool) error {
	log.Infof("here")
	times++
	if times > 1 {
		panic("oops")
	}
	s.lp.AddrManager().Start()
	defer func() {
		err := s.lp.AddrManager().Stop()
		if err != nil {
			log.Errorf("Failed to cleanly stop address manager: %v", err)
		}
	}()

	// Seed peers over DNS when not disabled by persistant peers.
	if len(s.persistantPeers) == 0 {
		s.lp.DNSSeed(wire.SFNodeNetwork | wire.SFNodeCF)
	}

	// Start background handlers to read received messages from remote peers
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return s.receiveGetData(gctx) })
	g.Go(func() error { return s.receiveInv(gctx) })
	g.Go(func() error { return s.receiveHeadersAnnouncements(gctx) })
	s.lp.AddHandledMessages(p2p.MaskGetData | p2p.MaskInv)

	if startupSync {
		// Load transaction filters with all active addresses and watched
		// outpoints.
		err := s.wallet.LoadActiveDataFilters(ctx, s)
		if err != nil {
			return err
		}
	}

	if len(s.persistantPeers) != 0 {
		for _, raddr := range s.persistantPeers {
			raddr := raddr
			go func() {
				rp, err := s.lp.ConnectOutbound(ctx, raddr, reqSvcs)
				if err != nil {
					log.Error(err)
					return
				}
				k := addrmgr.NetAddressKey(rp.NA())
				s.remotesMu.Lock()
				s.remotes[k] = rp
				s.remotesMu.Unlock()

				err = rp.Err()
				s.remotesMu.Lock()
				delete(s.remotes, k)
				s.remotesMu.Unlock()
			}()
		}
	} else {
		g.Go(func() error {
			sem := make(chan struct{}, 8)
			for {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return ctx.Err()
				}
				na, err := s.peerCandidate(reqSvcs)
				if err != nil {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(5 * time.Second):
						<-sem
						continue
					}
				}

				s.remotesMu.Lock()
				_, ok := s.remotes[addrmgr.NetAddressKey(na)]
				s.remotesMu.Unlock()
				if ok {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(5 * time.Second):
						<-sem
						continue
					}
				}

				go func() {
					defer func() { <-sem }()
					// Make outbound connections to remote peers.
					port := strconv.FormatUint(uint64(na.Port), 10)
					raddr := net.JoinHostPort(na.IP.String(), port)
					rp, err := s.lp.ConnectOutbound(ctx, raddr, reqSvcs)
					if err != nil {
						log.Error(err)
						return
					}
					k := addrmgr.NetAddressKey(na)
					s.remotesMu.Lock()
					s.remotes[k] = rp
					s.remotesMu.Unlock()

					err = rp.Err()
					s.remotesMu.Lock()
					delete(s.remotes, k)
					s.remotesMu.Unlock()
				}()
			}
		})
	}

	if startupSync {
		err := s.startupSync(ctx)
		if err != nil {
			return err
		}
	}

	// Request blocks to be announced using headers messages.
	s.remotesMu.Lock()
	for _, rp := range s.remotes {
		err := rp.SendHeaders(ctx)
		if err != nil {
			log.Warn(err)
		}
	}
	s.remotesMu.Unlock()

	// Wait until cancellation or a handler errors.
	return g.Wait()
}

func (s *Syncer) peerCandidate(svcs wire.ServiceFlag) (*wire.NetAddress, error) {
	// Try to obtain peer candidates at random, decreasing the requirements
	// as more tries are performed.
	for tries := 0; tries < 100; tries++ {
		kaddr := s.lp.AddrManager().GetAddress()
		if kaddr == nil {
			break
		}
		na := kaddr.NetAddress()

		// Skip peer if already connected
		// TODO: this should work with network blocks, not exact addresses.
		s.remotesMu.Lock()
		_, ok := s.remotes[addrmgr.NetAddressKey(na)]
		s.remotesMu.Unlock()
		if ok {
			continue
		}

		// Only allow recent nodes (10mins) after we failed 30 times
		if tries < 30 && time.Since(kaddr.LastAttempt()) < 10*time.Minute {
			continue
		}

		// Skip peers without matching service flags for the first 50 tries.
		if tries < 50 && kaddr.NetAddress().Services&svcs != svcs {
			continue
		}

		return na, nil
	}
	return nil, errors.New("no addresses")
}

func (s *Syncer) forRemotes(f func(rp *p2p.RemotePeer) error) error {
	defer s.remotesMu.Unlock()
	s.remotesMu.Lock()
	if len(s.remotes) == 0 {
		return ErrNoRemotePeers
	}
	for _, rp := range s.remotes {
		err := f(rp)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Syncer) pickRemote(pick func(*p2p.RemotePeer) bool) (*p2p.RemotePeer, error) {
	defer s.remotesMu.Unlock()
	s.remotesMu.Lock()

	for _, rp := range s.remotes {
		if pick(rp) {
			return rp, nil
		}
	}
	return nil, ErrNoRemotePeers
}

func (s *Syncer) receiveGetData(ctx context.Context) error {
	for {
		rp, msg, err := s.lp.ReceiveGetData(ctx)
		if err != nil {
			return err
		}
		go func() {
			// Ensure that the data was (recently) announced using an inv.
			var txHashes []*chainhash.Hash
			var notFound []*wire.InvVect
			for _, inv := range msg.InvList {
				if !rp.InvsSent().Contains(inv.Hash) {
					notFound = append(notFound, inv)
					continue
				}
				switch inv.Type {
				case wire.InvTypeTx:
					txHashes = append(txHashes, &inv.Hash)
				default:
					notFound = append(notFound, inv)
				}
			}

			var (
				foundTxs []*wire.MsgTx
			)

			// Search for requested transactions
			if len(txHashes) != 0 {
				var missing []*wire.InvVect
				var err error
				foundTxs, missing, err = s.wallet.GetTransactionsByHashes(txHashes)
				if err != nil && !errors.Is(errors.NotExist, err) {
					log.Warnf("Failed to look up transactions for getdata reply to peer %v: %v",
						rp.RemoteAddr(), err)
					return
				}
				if len(missing) != 0 {
					notFound = append(notFound, missing...)
				}
			}

			// Send all found transactions
			for _, tx := range foundTxs {
				err := rp.SendMessage(ctx, tx)
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					log.Warnf("Failed to send getdata reply to peer %v: %v",
						rp.RemoteAddr(), err)
				}
			}

			// Send notfound message for all missing or unannounced data.
			if len(notFound) != 0 {
				err := rp.SendMessage(ctx, &wire.MsgNotFound{notFound})
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					log.Warnf("Failed to send notfound reply to peer %v: %v",
						rp.RemoteAddr(), err)
				}
			}
		}()
	}
}

func (s *Syncer) receiveInv(ctx context.Context) error {
	for {
		rp, msg, err := s.lp.ReceiveInv(ctx)
		if err != nil {
			return err
		}

		go s.handleInv(ctx, rp, msg)
	}
}

func (s *Syncer) handleInv(ctx context.Context, rp *p2p.RemotePeer, msg *wire.MsgInv) {
	var blocks []*chainhash.Hash

	for _, inv := range msg.InvList {
		switch inv.Type {
		case wire.InvTypeBlock:
			blocks = append(blocks, &inv.Hash)

			// TODO: fetch tx, check if relevant, maybe add to mempool
			//case wire.InvTypeTx:
		}
	}

	if len(blocks) != 0 {
		s.handleBlockInvs(ctx, rp, blocks)
	}
}

func (s *Syncer) handleBlockInvs(ctx context.Context, rp *p2p.RemotePeer, hashes []*chainhash.Hash) {
	// Fetch all blocks and their cfilters.  It is not possible to verify a
	// cfilter without a header commitment, which the inv does not provide.
	var blocks []*wire.MsgBlock
	var filters []*gcs.Filter
	var g errgroup.Group
	g.Go(func() error {
		b, err := rp.GetBlocks(ctx, hashes)
		if err != nil {
			if ctx.Err() == nil {
				log.Warnf("Failed to fetch inventoried blocks from %v: %v",
					rp.RemoteAddr(), err)
			}
			return err
		}
		blocks = b
		return nil
	})
	g.Go(func() error {
		f, err := getCFilters(ctx, rp, hashes)
		if err != nil {
			return err
		}
		filters = f
		return nil
	})
	err := g.Wait()
	if err != nil {
		if ctx.Err() == nil {
			log.Warnf("Failed to fetch data in response to inventory message: %v", err)
		}
		return
	}

	// TODO: validate work is at or above the required target. This
	// requires API changes to the blockchain package so that
	// calculating the required target does not depend on a
	// blockchain.BlockChain.
	for _, block := range blocks {
		err := blockchain.CheckProofOfWork(&block.Header, s.wallet.ChainParams().PowLimit)
		if err != nil {
			log.Warnf("Peer %v provided block with invalid proof of work: %v",
				rp.RemoteAddr(), err)
			rp.Disconnect()
			return
		}
	}

	// TODO: validate cfilters (requires commitments)

	defer s.sidechainMu.Unlock()
	s.sidechainMu.Lock()

	for i, b := range blocks {
		header := b.Header // Shallow copy header to prevent leaking entire block
		s.sidechains.AddBlockNode(wallet.NewSidechainNode(&header, hashes[i], filters[i]))
	}

	bestChain, err := s.wallet.EvaluateBestChain(&s.sidechains)
	if err != nil {
		log.Warnf("Failed to evaluate best chain: %v", err)
		return
	}
	if len(bestChain) == 0 {
		return
	}

	// TODO: this does not check previously inventoried blocks
	relevantTxs := make(map[chainhash.Hash][]*wire.MsgTx)
NextNode:
	for _, n := range bestChain {
		for i, h := range hashes {
			if *n.Hash == *h {
				relevantTxs[*n.Hash] = s.rescanBlock(blocks[i])
				continue NextNode
			}
		}
	}

	_, err = s.wallet.ChainSwitch(bestChain, relevantTxs)
	if err != nil {
		log.Errorf("Failed to update main chain: %v", err)
		return
	}
}

func (s *Syncer) receiveHeadersAnnouncements(ctx context.Context) error {
	for {
		rp, headers, err := s.lp.ReceiveHeadersAnnouncement(ctx)
		if err != nil {
			return err
		}

		err = s.handleHeadersAnnouncements(ctx, rp, headers)
		if err != nil {
			return err
		}
	}
}

func (s *Syncer) handleHeadersAnnouncements(ctx context.Context, rp *p2p.RemotePeer, headers []*wire.BlockHeader) error {
	if len(headers) == 0 {
		return nil
	}

	blockHashes := make([]*chainhash.Hash, 0, len(headers))
	for _, h := range headers {
		hash := h.BlockHash()
		blockHashes = append(blockHashes, &hash)
	}
	filters, err := s.GetCFilters(ctx, blockHashes)
	if err != nil {
		if ctx.Err() == nil {
			log.Warnf("Peer %v failed to return cfilters for announced blocks: %v",
				rp.RemoteAddr(), err)
			rp.Disconnect()
		}
		return err
	}

	tipHash, _ := s.wallet.MainChainTip()
	if headers[0].PrevBlock != tipHash {
		for i := range headers {
			log.Infof("Received sidechain or orphan block %v, height %v",
				blockHashes[i], headers[i].Height)
			s.sidechains.AddBlockNode(wallet.NewSidechainNode(
				headers[i], blockHashes[i], filters[i]))
		}
	} else {
		// Discover which blocks may possibly hold relevant transactions
		matchingBlocks := make([]*chainhash.Hash, 0, len(headers))
		s.filterMu.Lock()
		for i, f := range filters {
			key := blockcf.Key(blockHashes[i])
			match := f.N() != 0 && f.MatchAny(key, s.filterData)
			if match {
				matchingBlocks = append(matchingBlocks, blockHashes[i])
			}
		}
		s.filterMu.Unlock()

		matchingTxs := make(map[chainhash.Hash][]*wire.MsgTx)
		if len(matchingBlocks) != 0 {
			blocks, err := rp.GetBlocks(ctx, matchingBlocks)
			if err != nil {
				if ctx.Err() == nil {
					log.Warnf("Peer %v failed to provide full block for announced block: %v",
						rp.RemoteAddr(), err)
					rp.Disconnect()
				}
				return err
			}
			// TODO: validate block
			for i, hash := range matchingBlocks {
				matchingTxs[*hash] = s.rescanBlock(blocks[i])
			}
		}

		// Build a chain that extends the wallet's main chain.
		chain := make([]*wallet.SidechainNode, 0, len(headers))
		for i := range headers {
			chain = append(chain, wallet.NewSidechainNode(
				headers[i], blockHashes[i], filters[i]))
		}

		// Extend the main chain
		removedChain, err := s.wallet.ChainSwitch(chain, matchingTxs)
		if err != nil {
			log.Warnf("Failed to extend main chain: %v", err)
			// Add failed blocks to sidechains to be processed later.
			for i, header := range headers {
				s.sidechains.AddBlockNode(wallet.NewSidechainNode(
					header, blockHashes[i], filters[i]))
			}
		}
		if len(removedChain) != 0 {
			log.Warnf("Performed a reorganize when expected to only extend " +
				"main chain")
			for _, n := range removedChain {
				s.sidechains.AddBlockNode(n)
			}
		}
	}

	// With new blocks attached to the main chain, or added to the sidechain
	// forest, check whether the main chain must be advanced or reorged.
	chain, err := s.wallet.EvaluateBestChain(&s.sidechains)
	if err != nil {
		log.Warnf("Failed to evaluate best side chain: %v", err)
		return nil
	}
	if chain == nil {
		return nil
	}

	// Discover which blocks may possibly hold relevant transactions
	matchingBlocks := make([]*chainhash.Hash, 0, len(headers))
	s.filterMu.Lock()
	for i, f := range filters {
		key := blockcf.Key(blockHashes[i])
		match := f.N() != 0 && f.MatchAny(key, s.filterData)
		if match {
			matchingBlocks = append(matchingBlocks, blockHashes[i])
		}
	}
	s.filterMu.Unlock()

	matchingTxs := make(map[chainhash.Hash][]*wire.MsgTx)
	if len(matchingBlocks) != 0 {
		blocks, err := rp.GetBlocks(ctx, matchingBlocks)
		if err != nil {
			if ctx.Err() == nil {
				log.Warnf("Peer %v failed to provide announced block: %v",
					rp.RemoteAddr(), err)
				rp.Disconnect()
			}
			return err
		}
		// TODO: validate block
		for i, hash := range matchingBlocks {
			matchingTxs[*hash] = s.rescanBlock(blocks[i])
		}
	}

	prevChain, err := s.wallet.ChainSwitch(chain, matchingTxs)
	if err != nil {
		return err
	}
	s.sidechains.PruneTree(chain[0].Hash)
	s.sidechains.Prune(int32(chain[len(chain)-1].Header.Height), s.wallet.ChainParams())
	for _, n := range prevChain {
		s.sidechains.AddBlockNode(n)
	}

	return nil
}

// startupSync brings the wallet up to date with the current chain server
// connection.  It creates a rescan request and blocks until the rescan has
// finished.
func (s *Syncer) startupSync(ctx context.Context) error {
	tipHash, tipHeight := s.wallet.MainChainTip()
	log.Infof("Currently synced through block %v height %d", &tipHash, tipHeight)

	// Fetch any missing main chain compact filters.
	err := s.wallet.FetchMissingCFilters(ctx, s)
	if err != nil {
		return err
	}

	// Fetch headers for unseen blocks in the main chain, determine whether a
	// rescan is necessary, and when to begin it.
	fetchedHeaderCount, rescanStart, _, _, _, err := s.wallet.FetchHeaders(ctx, s)
	if err != nil {
		return err
	}

	// Rescan when necessary.
	//
	// TODO: Rescanning and discovering additional address usage can be rolled
	// into the same operation as an optimizatino.
	if fetchedHeaderCount != 0 {
		// Discover any addresses for this wallet that have not yet been created.
		err = s.wallet.DiscoverActiveAddresses(ctx, s, &rescanStart, !s.wallet.Locked())
		if err != nil {
			return err
		}

		err := s.wallet.Rescan(ctx, s, &rescanStart)
		if err != nil {
			return err
		}
	}

	unminedTxs, err := s.wallet.UnminedTransactions()
	if err != nil {
		log.Errorf("Cannot load unmined transactions for resending: %v", err)
		unminedTxs = nil
	}
	for _, tx := range unminedTxs {
		txHash := tx.TxHash()
		err := s.PublishTransaction(ctx, tx)
		if err != nil {
			// TODO: Transactions should be removed if this is a double spend.
			log.Tracef("Could not resend transaction %v: %v", &txHash, err)
			continue
		}
		log.Tracef("Resent unmined transaction %v", &txHash)
	}

	log.Infof("Blockchain sync completed, wallet ready for general usage.")

	return nil
}
