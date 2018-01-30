// Copyright (c) 2015-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"fmt"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/gcs/blockcf"
	"github.com/decred/dcrd/hdkeychain"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrwallet/errors"
	"github.com/decred/dcrwallet/wallet/udb"
	"github.com/decred/dcrwallet/walletdb"
	"golang.org/x/crypto/ripemd160"
)

type blockAddrPushCache map[chainhash.Hash]map[string]struct{}

func (c blockAddrPushCache) addBlock(blockHash *chainhash.Hash, block *wire.MsgBlock) {
	pushes := make(map[string]struct{})
	c[*blockHash] = pushes
	reduceBlock(pushes, block.Transactions)
	reduceBlock(pushes, block.STransactions)
}

// reduceBlock adds the bytes of every script push for an address from a slice
// of block transactions to the blockAddrPushes set.
func reduceBlock(blockAddrPushes map[string]struct{}, txs []*wire.MsgTx) {
	for _, tx := range txs {
		for _, in := range tx.TxIn {
			// To handle P2SH redeem scripts, the last data push is interpeted
			// and handled the same as an output script. This has the potential
			// to find false positives since it isn't certain that the input
			// being redeemed is indeed P2SH.
			pushes, err := txscript.PushedData(in.SignatureScript)
			if err != nil || len(pushes) == 0 {
				continue
			}
			p2shPushes, err := txscript.PushedData(pushes[len(pushes)-1])
			if err == nil {
				pushes = pushes[:len(pushes)-1]
				for _, push := range p2shPushes {
					// Only worry about pubkey and script hashes
					if len(push) == ripemd160.Size {
						blockAddrPushes[string(push)] = struct{}{}
					}
				}
			}
			for _, push := range pushes {
				if len(push) == ripemd160.Size {
					blockAddrPushes[string(push)] = struct{}{}
				}
			}
		}
		for _, out := range tx.TxOut {
			pushes, err := txscript.PushedData(out.PkScript)
			if err != nil {
				continue
			}
			for _, push := range pushes {
				if len(push) == ripemd160.Size {
					blockAddrPushes[string(push)] = struct{}{}
				}
			}
		}
	}
}

func cacheMissingAddrPushes(ctx context.Context, n NetworkBackend, cache blockAddrPushCache,
	include []*chainhash.Hash) error {

	var fetchBlocks []*chainhash.Hash
	for _, b := range include {
		if _, ok := cache[*b]; !ok {
			fetchBlocks = append(fetchBlocks, b)
		}
	}
	if len(fetchBlocks) == 0 {
		return nil
	}
	blocks, err := n.GetBlocks(ctx, fetchBlocks)
	if err != nil {
		return err
	}
	for i, b := range blocks {
		cache.addBlock(fetchBlocks[i], b)
	}
	return nil
}

func (w *Wallet) filterBlocks(startBlock *chainhash.Hash, data [][]byte) ([]*chainhash.Hash, error) {
	var searchBlocks []*chainhash.Hash
	storage := make([]*udb.BlockCFilter, 2000)
	startHash := startBlock
	inclusive := true
	for {
		storage = storage[:cap(storage)]
		var filters []*udb.BlockCFilter
		err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
			var err error
			filters, err = w.TxStore.GetMainChainCFilters(dbtx, startHash,
				inclusive, storage)
			return err
		})
		if err != nil {
			return nil, err
		}
		if len(filters) == 0 {
			break
		}
		for _, f := range filters {
			if f.Filter.N() == 0 {
				continue
			}
			key := blockcf.Key(&f.BlockHash)
			if f.Filter.MatchAny(key, data) {
				h := f.BlockHash
				searchBlocks = append(searchBlocks, &h)
			}
		}
		startHash = &filters[len(filters)-1].BlockHash
		inclusive = false
	}
	return searchBlocks, nil
}

func (w *Wallet) findLastUsedAccount(ctx context.Context, n NetworkBackend, blockCache blockAddrPushCache,
	coinTypeXpriv *hdkeychain.ExtendedKey) (uint32, error) {

	const scanLen = 100
	var (
		lastUsed   uint32
		lo, hi     uint32 = 0, hdkeychain.HardenedKeyStart / scanLen
		gapLimit          = uint32(w.gapLimit)
		addrPushes        = make([][]byte, 0, scanLen*gapLimit*2)
	)
	for lo <= hi {
		mid := (hi + lo) / 2

		addrPushAccts := make(map[string]uint32)
		addrPushes = addrPushes[:0]

		for i := 0; i < scanLen; i++ {
			acct := mid*scanLen + uint32(i)
			if acct >= hdkeychain.HardenedKeyStart {
				break
			}
			xpriv, err := coinTypeXpriv.Child(hdkeychain.HardenedKeyStart + acct)
			if err != nil {
				return 0, err
			}
			xpub, err := xpriv.Neuter()
			if err != nil {
				xpriv.Zero()
				return 0, err
			}
			extKey, intKey, err := deriveBranches(xpub)
			if err != nil {
				xpriv.Zero()
				return 0, err
			}
			addrs, err := deriveChildAddresses(extKey, 0, gapLimit, w.chainParams)
			if err != nil {
				return 0, err
			}
			for _, a := range addrs {
				push := a.ScriptAddress()
				addrPushAccts[string(push)] = acct
				addrPushes = append(addrPushes, push)
			}
			addrs, err = deriveChildAddresses(intKey, 0, gapLimit, w.chainParams)
			if err != nil {
				return 0, err
			}
			for _, a := range addrs {
				push := a.ScriptAddress()
				addrPushAccts[string(push)] = acct
				addrPushes = append(addrPushes, push)
			}
		}

		searchBlocks, err := w.filterBlocks(w.chainParams.GenesisHash, addrPushes)
		if err != nil {
			return 0, err
		}

		// Fetch blocks that have not been fetched yet, and reduce them to a set
		// of addresses script pushes.
		err = cacheMissingAddrPushes(ctx, n, blockCache, searchBlocks)
		if err != nil {
			return 0, err
		}

		// Search matching blocks for account usage.
		for _, b := range searchBlocks {
			pushes := blockCache[*b]
			for _, push := range addrPushes {
				if _, ok := pushes[string(push)]; !ok {
					continue
				}

				// Address was found in this block.  Look up the address path
				// and update the last used address index in the usage
				// accordingly.
				acct := addrPushAccts[string(push)]
				log.Debugf("Found match for address push %x account %v in block %v",
					push, acct, b)

				if lastUsed < acct {
					lastUsed = acct
				}
			}
		}

		if mid == 0 {
			break
		}
		hi = mid - 1
	}
	return lastUsed, nil
}

type accountAddressUsage struct {
	externalBranch         *hdkeychain.ExtendedKey
	internalBranch         *hdkeychain.ExtendedKey
	externalLastUsed       uint32
	internalLastUsed       uint32
	externalLo, externalHi uint32 // Set to internal - 1 when finished, be cautious of unsigned underflow
	internalLo, internalHi uint32
}

type addressPath struct {
	account, branch, index uint32
}

// DiscoverActiveAddresses searches for future wallet address usage in all
// blocks starting from startBlock.  If discoverAccts is true, used accounts
// will be discovered as well.  This feature requires the wallet to be unlocked
// in order to derive hardened account extended pubkeys.
//
// If the wallet is currently on the legacy coin type and no address or account
// usage is observed, the wallet will be upgraded to the SLIP0044 coin type and
// the address discovery will occur again.
func (w *Wallet) DiscoverActiveAddresses(ctx context.Context, n NetworkBackend, startBlock *chainhash.Hash, discoverAccts bool) error {
	const op errors.Op = "wallet.DiscoverActiveAddresses"
	_, slip0044CoinType := udb.CoinTypes(w.chainParams)
	var activeCoinType uint32
	var coinTypeKnown, isSLIP0044CoinType bool
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		var err error
		activeCoinType, err = w.Manager.CoinType(dbtx)
		if errors.Is(errors.WatchingOnly, err) {
			return nil
		}
		if err != nil {
			return err
		}
		coinTypeKnown = true
		isSLIP0044CoinType = activeCoinType == slip0044CoinType
		log.Debugf("DiscoverActiveAddresses: activeCoinType=%d", activeCoinType)
		return nil
	})
	if err != nil {
		return errors.E(op, err)
	}

	// Map block hashes to a set of address script pushes from the block.  This
	// map is queried to avoid fetching the same block multiple times, and
	// blocks are reduced to a set of address script pushes as that is the only
	// thing being searched for.
	blockAddresses := make(blockAddrPushCache)

	// Start by rescanning the accounts and determining what the current account
	// index is. This scan should only ever be performed if we're restoring our
	// wallet from seed.
	if discoverAccts {
		log.Infof("Discovering used accounts")
		var coinTypePrivKey *hdkeychain.ExtendedKey
		defer func() {
			if coinTypePrivKey != nil {
				coinTypePrivKey.Zero()
			}
		}()
		err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			var err error
			coinTypePrivKey, err = w.Manager.CoinTypePrivKey(tx)
			return err
		})
		if err != nil {
			return errors.E(op, err)
		}
		lastUsed, err := w.findLastUsedAccount(ctx, n, blockAddresses, coinTypePrivKey)
		if err != nil {
			return errors.E(op, err)
		}
		if lastUsed != 0 {
			var lastRecorded uint32
			acctXpubs := make(map[uint32]*hdkeychain.ExtendedKey)
			w.addressBuffersMu.Lock()
			err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				var err error
				lastRecorded, err = w.Manager.LastAccount(ns)
				if err != nil {
					return err
				}
				for acct := lastRecorded + 1; acct <= lastUsed; acct++ {
					acct, err := w.Manager.NewAccount(ns, fmt.Sprintf("account-%d", acct))
					if err != nil {
						return err
					}
					xpub, err := w.Manager.AccountExtendedPubKey(tx, acct)
					if err != nil {
						return err
					}
					acctXpubs[acct] = xpub
				}
				return nil
			})
			if err != nil {
				w.addressBuffersMu.Unlock()
				return errors.E(op, err)
			}
			for acct := lastRecorded + 1; acct <= lastUsed; acct++ {
				_, ok := w.addressBuffers[acct]
				if !ok {
					extKey, intKey, err := deriveBranches(acctXpubs[acct])
					if err != nil {
						w.addressBuffersMu.Unlock()
						return errors.E(op, err)
					}
					w.addressBuffers[acct] = &bip0044AccountData{
						albExternal: addressBuffer{branchXpub: extKey},
						albInternal: addressBuffer{branchXpub: intKey},
					}
				}
			}
			w.addressBuffersMu.Unlock()
		}
	}

	var lastAcct uint32
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error
		lastAcct, err = w.Manager.LastAccount(ns)
		return err
	})
	if err != nil {
		return errors.E(op, err)
	}

	log.Infof("Discovering used addresses for %d account(s)", lastAcct+1)

	// Scan for address usage for the both the internal and external branches of
	// all accounts.
	var (
		scanLen  = uint32(w.gapLimit)
		segments = hdkeychain.HardenedKeyStart / scanLen
		usage    = make([]accountAddressUsage, 0, lastAcct+1)
	)
	err = walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		for acct := uint32(0); acct <= lastAcct; acct++ {
			external, err := w.Manager.AccountBranchExtendedPubKey(dbtx, acct, 0)
			if err != nil {
				return err
			}
			internal, err := w.Manager.AccountBranchExtendedPubKey(dbtx, acct, 1)
			if err != nil {
				return err
			}
			usage = append(usage, accountAddressUsage{
				externalBranch:   external,
				internalBranch:   internal,
				externalLastUsed: ^uint32(0),
				internalLastUsed: ^uint32(0),
				externalLo:       0,
				externalHi:       segments - 1,
				internalLo:       0,
				internalHi:       segments - 1,
			})
		}
		return nil
	})
	if err != nil {
		return err
	}

	for {
		// Derive all addresses for all accounts that must be scanned this
		// iteration, and mark them in a map that associates the script push
		// back to the correct account, branch, and index path so the usage
		// slice can be updated if the address is found used.
		var addrPushes [][]byte
		addrPaths := make(map[string]addressPath)
		for i := range usage {
			extlo, exthi := usage[i].externalLo, usage[i].externalHi
			intlo, inthi := usage[i].internalLo, usage[i].internalHi
			if extlo <= exthi && exthi+1 != extlo {
				mid := (exthi + extlo) / 2
				addrs, err := deriveChildAddresses(usage[i].externalBranch,
					mid*scanLen, scanLen, w.chainParams)
				if err != nil {
					return err
				}
				for j, a := range addrs {
					push := a.ScriptAddress()
					addrPushes = append(addrPushes, push)
					addrPaths[string(push)] = addressPath{
						account: uint32(i),
						branch:  0,
						index:   mid*scanLen + uint32(j),
					}
				}
			}
			if intlo <= inthi && inthi+1 != intlo {
				mid := (inthi + intlo) / 2
				addrs, err := deriveChildAddresses(usage[i].internalBranch,
					mid*scanLen, scanLen, w.chainParams)
				if err != nil {
					return err
				}
				for j, a := range addrs {
					push := a.ScriptAddress()
					addrPushes = append(addrPushes, push)
					addrPaths[string(push)] = addressPath{
						account: uint32(i),
						branch:  1,
						index:   mid*scanLen + uint32(j),
					}
				}
			}
		}

		if len(addrPushes) == 0 {
			break
		}

		searchBlocks, err := w.filterBlocks(startBlock, addrPushes)
		if err != nil {
			return err
		}

		// Fetch blocks that have not been fetched yet, and reduce them to a set
		// of addresses script pushes.
		err = cacheMissingAddrPushes(ctx, n, blockAddresses, searchBlocks)
		if err != nil {
			return err
		}

		// Search matching blocks for address usage.
		for _, b := range searchBlocks {
			pushes := blockAddresses[*b]
			for _, push := range addrPushes {
				if _, ok := pushes[string(push)]; !ok {
					continue
				}

				// Address was found in this block.  Look up the address path
				// and update the last used address index in the usage
				// accordingly.
				path := addrPaths[string(push)]
				log.Debugf("Found match for address push %x path %v in block %v", push, path, b)
				acctUsage := &usage[path.account]
				switch path.branch {
				case 0: // external
					if acctUsage.externalLastUsed == ^uint32(0) ||
						path.index > acctUsage.externalLastUsed {
						acctUsage.externalLastUsed = path.index
					}
				case 1: // internal
					if acctUsage.internalLastUsed == ^uint32(0) ||
						path.index > acctUsage.internalLastUsed {
						acctUsage.internalLastUsed = path.index
					}
				}
			}
		}

		// Update each account's external and internal hi/lo segments for the
		// next bisect iteration.
		for i := range usage {
			u := &usage[i]
			if u.externalLo <= u.externalHi {
				mid := (u.externalHi + u.externalLo) / 2
				// When the last used index is in this segment's index half open
				// range [begin,end) then an address was found in this segment.
				begin := mid * scanLen
				end := begin + scanLen
				if u.externalLastUsed >= begin && u.externalLastUsed < end {
					u.externalLo = mid + 1
				} else {
					u.externalHi = mid - 1
				}
			}
			if u.internalLo <= u.internalHi {
				mid := (u.internalHi + u.internalLo) / 2
				begin := mid * scanLen
				end := begin + scanLen
				if u.internalLastUsed >= begin && u.internalLastUsed < end {
					u.internalLo = mid + 1
				} else {
					u.internalHi = mid - 1
				}
			}
		}
	}

	// Save discovered addresses for each account plus additional future
	// addresses that may be used by other wallets sharing the same seed.
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		gapLimit := uint32(w.gapLimit)

		for i := range usage {
			u := &usage[i]
			acct := uint32(i)

			// SyncAccountToAddrIndex never removes derived addresses
			// from an account, and can be called with just the
			// discovered last used child index, plus the gap limit.
			// Cap it to the highest child index.
			//
			// If no addresses were used for this branch, lastUsed is
			// ^uint32(0) and adding the gap limit it will sync exactly
			// gapLimit number of addresses (e.g. 0-19 when the gap
			// limit is 20).
			err := w.Manager.SyncAccountToAddrIndex(ns, acct,
				minUint32(u.externalLastUsed+gapLimit, hdkeychain.HardenedKeyStart-1),
				0)
			if err != nil {
				return err
			}
			if u.externalLastUsed < hdkeychain.HardenedKeyStart {
				err = w.Manager.MarkUsedChildIndex(tx, acct, 0, u.externalLastUsed)
				if err != nil {
					return err
				}
			}
			err = w.Manager.SyncAccountToAddrIndex(ns, acct,
				minUint32(u.internalLastUsed+gapLimit, hdkeychain.HardenedKeyStart-1),
				1)
			if err != nil {
				return err
			}
			if u.internalLastUsed < hdkeychain.HardenedKeyStart {
				err = w.Manager.MarkUsedChildIndex(tx, acct, 1, u.internalLastUsed)
				if err != nil {
					return err
				}
			}

			props, err := w.Manager.AccountProperties(ns, acct)
			if err != nil {
				return err
			}

			// Update last used index and cursor for this account's address
			// buffers.
			w.addressBuffersMu.Lock()
			acctData := w.addressBuffers[acct]
			acctData.albExternal.lastUsed = props.LastUsedExternalIndex
			acctData.albExternal.cursor = props.LastReturnedExternalIndex - props.LastUsedExternalIndex
			acctData.albInternal.lastUsed = props.LastUsedInternalIndex
			acctData.albInternal.cursor = props.LastReturnedInternalIndex - props.LastUsedInternalIndex
			w.addressBuffersMu.Unlock()

			// Unfortunately if the cursor is equal to or greater than
			// the gap limit, the next child index isn't completely
			// known.  Depending on the gap limit policy being used, the
			// next address could be the index after the last returned
			// child or the child may wrap around to a lower value.
			log.Infof("Synchronized account %d branch 0 to next child index %v",
				acct, props.LastReturnedExternalIndex+1)
			log.Infof("Synchronized account %d branch 1 to next child index %v",
				acct, props.LastReturnedInternalIndex+1)
		}

		return nil
	})
	if err != nil {
		return errors.E(op, err)
	}

	log.Infof("Finished address discovery")

	// If the wallet does not know the current coin type (e.g. it is a watching
	// only wallet created from an account master pubkey) or when the wallet
	// uses the SLIP0044 coin type, there is nothing more to do.
	if !coinTypeKnown || isSLIP0044CoinType {
		return nil
	}

	// Do not upgrade legacy coin type wallets if there are returned or used
	// addresses.
	if !isSLIP0044CoinType && (len(usage) != 0 || usage[0].externalLastUsed != ^uint32(0) ||
		usage[0].internalLastUsed != ^uint32(0)) {
		log.Warnf("Wallet contains addresses derived for the legacy BIP0044 " +
			"coin type and seed restores may not work with some other wallet " +
			"software")
		return nil
	}

	// Upgrade the coin type.
	log.Infof("Upgrading wallet from legacy coin type %d to SLIP0044 coin type %d",
		activeCoinType, slip0044CoinType)
	err = w.UpgradeToSLIP0044CoinType()
	if err != nil {
		log.Errorf("Coin type upgrade failed: %v", err)
		log.Warnf("Continuing with legacy BIP0044 coin type -- seed restores " +
			"may not work with some other wallet software")
		return nil
	}
	log.Infof("Upgraded coin type.")

	// Perform address discovery a second time using the upgraded coin type.
	return w.DiscoverActiveAddresses(ctx, n, startBlock, discoverAccts)
}
