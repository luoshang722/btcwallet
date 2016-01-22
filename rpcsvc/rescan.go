// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpcsvc

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// rescanProgressMsg reports the current progress made by a rescan for a set of
// wallet addresses.
type rescanProgressMsg struct {
	addresses    []btcutil.Address
	notification *rescanProgress
}

// rescanJob is a collection of one or more RescanJobs that were merged
// together before a rescan is performed.
type rescanJob struct {
	initialSync bool
	addrs       []btcutil.Address
	outpoints   []*wire.OutPoint
	bs          waddrmgr.BlockStamp
	errChans    []chan error
}

// submitRescan submits a rescan job.  A channel is returned with the final
// error of the rescan.  The channel is buffered and does not need to be read to
// prevent a deadlock.
func (s *SynchronizationService) submitRescan(job *rescanJob) <-chan error {
	errChan := make(chan error, 1)
	job.errChans = []chan error{errChan}
	s.rescanAddJob <- job
	return errChan
}

// merge merges the work from b into job, setting the starting height to the
// minimum of the two jobs.  This method does not check for duplicate addresses
// or outpoints.
func (b *rescanJob) merge(job *rescanJob) {
	if job.initialSync {
		b.initialSync = true
	}
	b.addrs = append(b.addrs, job.addrs...)
	b.outpoints = append(b.outpoints, job.outpoints...)
	if job.bs.Height < b.bs.Height {
		b.bs = job.bs
	}
	b.errChans = append(b.errChans, job.errChans...)
}

// done iterates through all error channels, duplicating sending the error to
// inform callers that the rescan finished (or could not complete due to an
// error).
func (b *rescanJob) done(err error) {
	for _, c := range b.errChans {
		c <- err
	}
}

func (s *SynchronizationService) rescanHandler(w *wallet.Wallet) {
	addJob := s.rescanAddJob
	rescanFuture := make(chan error)
	rescanProgress := s.rescanProgress
	rescanResults := s.rescanResults
	quit := s.quit
	var currentJob, nextJob *rescanJob
	var pendingResults []wallet.RescanResult

	beginRescan := func(job *rescanJob) {
		go func() {
			r := s.rpcClient.RescanAsync(&job.bs.Hash, job.addrs,
				job.outpoints)
			rescanFuture <- r.Receive()
		}()
	}
out:
	for {
		select {
		case job := <-addJob:
			// A new job can either be started immediatelly, set as
			// a pending job if a rescan is currently active and a
			// pending job does not yet exist, or be merged with an
			// existing pending job.
			if currentJob == nil {
				// Set current batch as this job and send
				currentJob, nextJob = job, nil
				beginRescan(job)

				// Log the newly-started rescan.
				numAddrs := len(currentJob.addrs)
				noun := pickNoun(numAddrs, "address", "addresses")
				log.Infof("Started rescan from block %v (height %d) for %d %s",
					currentJob.bs.Hash, currentJob.bs.Height,
					numAddrs, noun)
			} else if nextJob == nil {
				nextJob = job
			} else {
				nextJob.merge(job)
			}

		case err := <-rescanFuture:
			// If the rescan finished without error, wait for the
			// last progress notification.  Otherwise, send the
			// error now to all of the callers for this rescan job.
			// A new job can be started if it exists.
			if err != nil {
				currentJob.done(err)
				currentJob, nextJob = nextJob, nil
				if currentJob != nil {
					beginRescan(currentJob)
				}
			}

		case n := <-rescanProgress:
			if currentJob == nil {
				log.Warnf("Received rescan progress " +
					"notification while not " +
					"rescanning -- ignoring")
				continue
			}

			err := w.ProcessRescanResults(pendingResults, &n.block.Block)
			pendingResults = nil
			if n.finished {
				currentJob.done(err)

				addrs := currentJob.addrs
				noun := pickNoun(len(addrs), "address", "addresses")
				log.Infof("Finished rescan for %d %s (synced "+
					"to block %s, height %d)", len(addrs),
					noun, n.block.Hash, n.block.Height)

				go func() {
					err := s.sendUnminedTxs(w)
					if err != nil {
						log.Infof("Failed to send "+
							"unmined transactions:", err)
					}
				}()

				currentJob, nextJob = nextJob, nil
				if currentJob != nil {
					beginRescan(currentJob)
				}
			} else {
				log.Infof("Rescanned through block %v (height %d)",
					n.block.Hash, n.block.Height)
			}

		case n := <-rescanResults:
			if rescanFuture == nil {
				log.Warnf("Received unexpected " +
					"rescan result while not " +
					"rescanning -- ignoring")
				continue
			}
			pendingResults = append(pendingResults, n)

		case <-quit:
			break out
		}
	}

	s.wg.Done()
}

// initialRescan begins a rescan for all active addresses and unspent outputs of
// a wallet.  This is used to sync a wallet back up to the current best block in
// the main chain, and is considered an initial sync rescan.
func (s *SynchronizationService) initialRescan(addrs []btcutil.Address,
	unspent []wtxmgr.Credit, bs waddrmgr.BlockStamp) error {

	outpoints := make([]*wire.OutPoint, len(unspent))
	for i, output := range unspent {
		outpoints[i] = &output.OutPoint
	}

	job := &rescanJob{
		initialSync: true,
		addrs:       addrs,
		outpoints:   outpoints,
		bs:          bs,
	}

	// Submit merged job and block until rescan completes.
	return <-s.submitRescan(job)
}
