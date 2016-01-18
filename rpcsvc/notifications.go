/*
 * Copyright (c) 2013-2015 The btcsuite developers
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package rpcsvc

import (
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcrpcclient"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

func callbacks(s *SynchronizationService) *btcrpcclient.NotificationHandlers {
	return &btcrpcclient.NotificationHandlers{
		OnBlockConnected:    s.onBlockConnected,
		OnBlockDisconnected: s.onBlockDisconnected,
		OnRecvTx:            s.onRelevantTx,
		OnRedeemingTx:       s.onRelevantTx,
		OnRescanFinished:    s.onRescanFinished,
		OnRescanProgress:    s.onRescanProgress,
	}
}

// Notification types.  These are defined here and processed from from reading
// a notificationChan to avoid handling these notifications directly in
// btcrpcclient callbacks, which isn't very Go-like and doesn't allow
// blocking client calls.
type (
	// clientConnected is a notification for when a client connection is
	// opened or reestablished to the chain server.
	clientConnected struct{}

	// blockConnected is a notification for a newly-attached block to the
	// best chain.
	blockConnected struct {
		block         wtxmgr.BlockMeta
		subscribedTxs []wire.MsgTx
	}

	// blockDisconnected is a notifcation that the block described by the
	// BlockStamp was reorganized out of the best chain.
	blockDisconnected wtxmgr.BlockMeta

	// relevantTx is a notification for a transaction which spends wallet
	// inputs or pays to a watched address.  rescanBlock is only non-nil
	// when describing a rescan result.  Otherwise, the transaction is a
	// relevant transaction accepted to the memory pool.
	relevantTx struct {
		txRecord    *wtxmgr.TxRecord
		rescanBlock *wtxmgr.BlockMeta
	}

	// rescanProgress is a notification describing the current status
	// of an in-progress rescan.
	rescanProgress struct {
		block    wtxmgr.BlockMeta
		finished bool
	}
)

// parseBlock parses a btcws definition of the block a tx is mined it to the
// Block structure of the wtxmgr package, and the block index.  This is done
// here since btcrpcclient doesn't parse this nicely for us.
func parseBlock(block *btcjson.BlockDetails) (*wtxmgr.BlockMeta, error) {
	if block == nil {
		return nil, nil
	}
	blksha, err := wire.NewShaHashFromStr(block.Hash)
	if err != nil {
		return nil, err
	}
	blk := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Height: block.Height,
			Hash:   *blksha,
		},
		Time: time.Unix(block.Time, 0),
	}
	return blk, nil
}

func (s *SynchronizationService) onBlockConnected(hash *wire.ShaHash, height int32,
	time time.Time, subscribedTxs []wire.MsgTx) {

	n := blockConnected{
		block: wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				Hash:   *hash,
				Height: height,
			},
			Time: time,
		},
		subscribedTxs: subscribedTxs,
	}
	select {
	case s.enqueueNotification <- n:
	case <-s.quit:
	}
}

func (s *SynchronizationService) onBlockDisconnected(hash *wire.ShaHash, height int32, time time.Time) {
	n := blockDisconnected{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: time,
	}
	select {
	case s.enqueueNotification <- n:
	case <-s.quit:
	}
}

func (s *SynchronizationService) onRelevantTx(tx *btcutil.Tx, block *btcjson.BlockDetails) {
	blk, err := parseBlock(block)
	if err != nil {
		// Log and drop improper notification.
		log.Errorf("recvtx/redeemingtx notification bad block: %v", err)
		return
	}

	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx.MsgTx(), time.Now())
	if err != nil {
		log.Errorf("Cannot create transaction record for relevant "+
			"tx: %v", err)
		return
	}
	select {
	case s.enqueueNotification <- relevantTx{rec, blk}:
	case <-s.quit:
	}
}

func (s *SynchronizationService) onRescanProgress(hash *wire.ShaHash, height int32, blkTime time.Time) {
	n := &rescanProgress{
		block: wtxmgr.BlockMeta{
			Block: wtxmgr.Block{*hash, height},
			Time:  blkTime,
		},
		finished: false,
	}
	select {
	case s.enqueueNotification <- n:
	case <-s.quit:
	}
}

func (s *SynchronizationService) onRescanFinished(hash *wire.ShaHash, height int32, blkTime time.Time) {
	n := &rescanProgress{
		block: wtxmgr.BlockMeta{
			Block: wtxmgr.Block{*hash, height},
			Time:  blkTime,
		},
		finished: true,
	}
	select {
	case s.enqueueNotification <- n:
	case <-s.quit:
	}

}

// notificationQueueHandler maintains a queue of RPC notifications.  If no
// notifications are received over some duration, a ping is used detect if the
// server is still available.  Synchronization ends if a pong is not received
// soon enough.
func (s *SynchronizationService) notificationQueueHandler() {
	// TODO: Rather than leaving this as an unbounded queue for all types of
	// notifications, try dropping ones where a later enqueued notification
	// can fully invalidate one waiting to be processed.  For example,
	// blockconnected notifications for greater block heights can remove the
	// need to process earlier blockconnected notifications still waiting
	// here.

	var notifications []interface{}
	enqueue := s.enqueueNotification
	var dequeue chan interface{}
	var next interface{}
	pingChan := time.After(time.Minute)
out:
	for {
		select {
		case n := <-enqueue:
			if len(notifications) == 0 {
				next = n
				dequeue = s.dequeueNotification
			}
			notifications = append(notifications, n)
			pingChan = time.After(time.Minute)

		case dequeue <- next:
			notifications[0] = nil
			notifications = notifications[1:]
			if len(notifications) != 0 {
				next = notifications[0]
			} else {
				dequeue = nil
			}

		case <-pingChan:
			// No notifications were received in the last 60s.
			// Ensure the connection is still active by making a new
			// request to the server.
			// TODO: A minute timeout is used to prevent the handler
			// loop from blocking here forever, but this is much larger
			// than it needs to be due to btcd processing websocket
			// requests synchronously (see
			// https://github.com/btcsuite/btcd/issues/504).  Decrease
			// this to something saner like 3s when the above issue is
			// fixed.
			type sessionResult struct {
				err error
			}
			sessionResponse := make(chan sessionResult, 1)
			go func() {
				_, err := s.rpcClient.Session()
				sessionResponse <- sessionResult{err}
			}()

			select {
			case resp := <-sessionResponse:
				if resp.err != nil {
					log.Errorf("Failed to receive session "+
						"result: %v", resp.err)
					break out
				}
				pingChan = time.After(time.Minute)

			case <-time.After(time.Minute):
				log.Errorf("Timeout waiting for session RPC")
				break out
			}

		case <-s.quit:
			break out
		}
	}

	s.stopSynchronization()
	close(s.dequeueNotification)
	s.wg.Done()
}
