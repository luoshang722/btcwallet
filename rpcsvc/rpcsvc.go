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

// Package rpcsvc provides Bitcoin consensus and network services for a wallet
// over a RPC backend.  It is responsible for modifying wallet state based on
// changes to the network (such as attached and detached blocks and relevant
// transactions in mempool) and providing the means by which a wallet interacts
// with the network by publishing transactions.
//
// The primary goal of this package is to separate the network services out of
// the wallet itself and at a high level, implement a method interface
// compatible with SPV clients.
package rpcsvc

import (
	"errors"
	"sync"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcrpcclient"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/internal/cfgutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var errUnimplemented = errors.New("unimplemented")

// SynchronizationService provides a websocket RPC backend for a wallet to
// synchronize it with the network and provide the ability to send transactions
// signed by the wallet.
//
// In the future, this type is expected to share an interface with a similar
// service that uses SPV for synchronization.
type SynchronizationService struct {
	rpcClient *btcrpcclient.Client

	connConfig          *btcrpcclient.ConnConfig
	enqueueNotification chan interface{}
	dequeueNotification chan interface{}

	rescanAddJob   chan *rescanJob
	rescanProgress chan *rescanProgress
	rescanResults  chan wallet.RescanResult

	wg     sync.WaitGroup
	quit   chan struct{}
	quitMu sync.Mutex
}

// RPCOptions specifies the connection options for a websocket RPC client that
// is able to synchronize a wallet.  If Certs has zero len, TLS will be
// disabled.  TLS may only be disabled when connecting to a localhost address.
type RPCOptions struct {
	NetworkAddress string
	Username       string
	Password       string
	Certs          []byte
}

func connConfig(opts *RPCOptions) *btcrpcclient.ConnConfig {
	return &btcrpcclient.ConnConfig{
		Host:                 opts.NetworkAddress,
		Endpoint:             "ws",
		User:                 opts.Username,
		Pass:                 opts.Password,
		Certificates:         opts.Certs,
		DisableAutoReconnect: true, // Caller is responsible for restarting service.
		DisableConnectOnNew:  true,
		DisableTLS:           len(opts.Certs) == 0,
	}
}

// NewSynchronizationService creates a new RPC client and synchronziation
// service to keeping a wallet up to date.  Once created, synchronization can be
// started by running the SynchronizeWallet function.
//
// Note that while a wallet pointer is needed for the service to actually make
// changes to the wallet, the wallet is passed in as a parameter to
// SynchronizeWallet rather than this constructor function.  This allows both
// the synchronization service and the wallets to be created or opened at
// different times in any order, and only when both are available can
// synchronization begin.
func NewSynchronizationService(opts *RPCOptions) (*SynchronizationService, error) {
	tlsRequired, err := cfgutil.TLSRequired(opts.NetworkAddress)
	if err != nil {
		return nil, err
	}
	if tlsRequired && len(opts.Certs) == 0 {
		return nil, errors.New("TLS is required")
	}

	s := &SynchronizationService{
		connConfig:          connConfig(opts),
		enqueueNotification: make(chan interface{}),
		dequeueNotification: make(chan interface{}),
		rescanAddJob:        make(chan *rescanJob),
		rescanProgress:      make(chan *rescanProgress),
		rescanResults:       make(chan wallet.RescanResult),
		quit:                make(chan struct{}),
	}

	rpcClient, err := btcrpcclient.New(s.connConfig, callbacks(s))
	if err != nil {
		return nil, err
	}
	err = rpcClient.Connect(0)
	if err != nil {
		return nil, err
	}

	s.rpcClient = rpcClient
	return s, nil
}

// SynchronizeWallet associates a wallet with the consensus RPC client,
// synchronizes the wallet with the latest changes to the blockchain, and
// continuously updates the wallet through RPC notifications.
//
// This function does not return without error until the wallet is synchronized
// to the current chain state.
func (s *SynchronizationService) SynchronizeWallet(w *wallet.Wallet) error {
	// Verify that the remote server is running on the expected network.
	net, err := s.rpcClient.GetCurrentNet()
	if err != nil {
		return err
	}
	if net != w.ChainParams().Net {
		return errors.New("mismatched networks")
	}

	s.wg.Add(3)
	go s.notificationQueueHandler()
	go s.processQueuedNotifications(w)
	go s.rescanHandler(w)

	return s.syncWithNetwork(w)
}

func (s *SynchronizationService) stopSynchronization() {
	s.quitMu.Lock()
	select {
	case <-s.quit:
	default:
		s.rpcClient.Shutdown()
		close(s.quit)
	}
	s.quitMu.Unlock()
}

// StopSynchronization shuts down the synchronization service if it is running.
// It returns a function that blocks until all synchronization goroutines have
// exited.
func (s *SynchronizationService) StopSynchronization() (waitFunc func()) {
	s.stopSynchronization()
	return s.wg.Wait
}

// RPCClient returns the underlying RPC client for the service.
func (s *SynchronizationService) RPCClient() *btcrpcclient.Client {
	return s.rpcClient
}

// POSTClient creates a new RPC client but configures it to use HTTP POST mode.
func (s *SynchronizationService) POSTClient() (*btcrpcclient.Client, error) {
	configCopy := *s.connConfig
	configCopy.HTTPPostMode = true
	return btcrpcclient.New(&configCopy, nil)
}

func (s *SynchronizationService) processQueuedNotifications(w *wallet.Wallet) {
	for n := range s.dequeueNotification {
		var err error
	notificationSwitch:
		switch n := n.(type) {
		case blockConnected:
			// At the moment all notified transactions are assumed
			// to actually be relevant.  This assumption will not
			// hold true when SPV support is added, but until then,
			// simply insert the transaction because there should
			// either be one or more relevant inputs or outputs.
			txRecords := make([]*wtxmgr.TxRecord, len(n.subscribedTxs))
			for i, tx := range n.subscribedTxs {
				// The serialized transaction was already sent
				// as part of the RPC notification so this could
				// be optimized a little.
				txRecords[i], err = wtxmgr.NewTxRecordFromMsgTx(&tx,
					n.block.Time)
				if err != nil {
					break notificationSwitch
				}
			}
			err = w.ProcessAttachedBlock(&n.block, txRecords)

		case blockDisconnected:
			err = w.ProcessDetachedBlock(n.Height, &n.Hash)

		case relevantTx:
			// Transactions with no block are notifiations of
			// relevant transactions just added to the memory pool.
			// If the block is set, then the transaction must be a
			// rescan result instead.  Pass rescan results to the
			// rescan goroutines as these results are processed
			// independently of the normal transactions and blocks.
			if n.rescanBlock != nil {
				s.rescanResults <- wallet.RescanResult{
					Transaction: n.txRecord,
					Block:       n.rescanBlock,
				}
				continue
			}

			err = w.ProcessUnminedTransaction(n.txRecord)

		// Rescan notifications are handled asynchronously from normal
		// block processing.
		case *rescanProgress:
			s.rescanProgress <- n
		}

		// TODO: If the wallet could not handle the notification,
		// synchronization should stop sinc it cannot reliably continue.
		if err != nil {
			log.Errorf("Cannot handle chain server "+
				"notification: %v", err)
		}
	}
	s.wg.Done()
}

// syncWithNetwork brings the wallet up to date with the current chain server
// connection.  It creates a rescan request and blocks until the rescan has
// finished.
func (s *SynchronizationService) syncWithNetwork(w *wallet.Wallet) error {
	chainClient := s.rpcClient

	// Request notifications for connected and disconnected blocks.
	//
	// TODO(jrick): Either request this notification only once, or when
	// btcrpcclient is modified to allow some notification request to not
	// automatically resent on reconnect, include the notifyblocks request
	// as well.  I am leaning towards allowing off all btcrpcclient
	// notification re-registrations, in which case the code here should be
	// left as is.
	err := chainClient.NotifyBlocks()
	if err != nil {
		return err
	}

	// Request notifications for transactions sending to all wallet
	// addresses.
	addrs, unspent, err := w.ActiveData()
	if err != nil {
		return err
	}

	// TODO(jrick): How should this handle a synced height earlier than
	// the chain server best block?

	// When no addresses have been generated for the wallet, the rescan can
	// be skipped.
	//
	// TODO: This is only correct because activeData above returns all
	// addresses ever created, including those that don't need to be watched
	// anymore.  This code should be updated when this assumption is no
	// longer true, but worst case would result in an unnecessary rescan.
	if len(addrs) == 0 && len(unspent) == 0 {
		// TODO: It would be ideal if on initial sync wallet saved the
		// last several recent blocks rather than just one.  This would
		// avoid a full rescan for a one block reorg of the current
		// chain tip.
		hash, height, err := chainClient.GetBestBlock()
		if err != nil {
			return err
		}
		return w.Manager.SetSyncedTo(&waddrmgr.BlockStamp{
			Hash:   *hash,
			Height: height,
		})
	}

	// Compare previously-seen blocks against the chain server.  If any of
	// these blocks no longer exist, rollback all of the missing blocks
	// before catching up with the rescan.
	iter := w.Manager.NewIterateRecentBlocks()
	rollback := iter == nil
	syncBlock := waddrmgr.BlockStamp{
		Hash:   *w.ChainParams().GenesisHash,
		Height: 0,
	}
	for cont := iter != nil; cont; cont = iter.Prev() {
		bs := iter.BlockStamp()
		log.Debugf("Checking for previous saved block with height %v hash %v",
			bs.Height, bs.Hash)
		_, err = chainClient.GetBlock(&bs.Hash)
		if err != nil {
			rollback = true
			continue
		}

		log.Debug("Found matching block.")
		syncBlock = bs
		break
	}
	if rollback {
		err = w.Manager.SetSyncedTo(&syncBlock)
		if err != nil {
			return err
		}
		// Rollback unconfirms transactions at and beyond the passed
		// height, so add one to the new synced-to height to prevent
		// unconfirming txs from the synced-to block.
		err = w.TxStore.Rollback(syncBlock.Height + 1)
		if err != nil {
			return err
		}
	}

	return s.initialRescan(addrs, unspent, w.Manager.SyncedTo())
}

// SendUnminedTxs iterates through all transactions that spend from wallet
// credits that are not known to have been mined into a block, and attempts to
// send each to the chain server for relay.
//
// TODO: This should return an error if any of these lookups or sends fail, but
// since send errors due to double spends need to be handled gracefully and this
// isn't done yet, all sending errors are simply logged.
func (s *SynchronizationService) SendUnminedTxs(w *wallet.Wallet) error {
	txs, err := w.TxStore.UnminedTxs()
	if err != nil {
		return err
	}
	rpcClient := s.rpcClient
	for _, tx := range txs {
		resp, err := rpcClient.SendRawTransaction(tx, false)
		if err != nil {
			// TODO(jrick): Check error for if this tx is a double spend,
			// remove it if so.
			log.Debugf("Could not resend transaction %v: %v",
				tx.TxSha(), err)
			continue
		}
		log.Debugf("Resent unmined transaction %v", resp)
	}
	return nil
}

func (s *SynchronizationService) WatchAddresses(addrs []btcutil.Address) error {
	return s.rpcClient.NotifyReceived(addrs)
}

func (s *SynchronizationService) SearchForUnspentOutputs() error {
	return errUnimplemented
}

// PublishTransaction sends the transaction to the consensus RPC server so it
// can be propigated to other nodes and eventually mined.
func (s *SynchronizationService) PublishTransaction(tx *wire.MsgTx) error {
	return errUnimplemented
}
