// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"math/big"
	"sort"

	"github.com/decred/dcrd/blockchain"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/gcs"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrwallet/walletdb"
)

// SidechainForest provides in-memory management of sidechain and orphan blocks.
// It implements a forest of disjoint rooted trees, each tree containing
// sidechains stemming from a different fork point in the main chain, or
// orphans.
//
// SidechainForest is not safe for concurrent access.
type SidechainForest struct {
	trees []*sidechainRootedTree
}

// SidechainNode represents a block node for a SidechainForest.  SidechainNodes
// are not safe for concurrent access, and all exported fields must be treated
// as immutable.
type SidechainNode struct {
	Header  *wire.BlockHeader
	Hash    *chainhash.Hash
	Filter  *gcs.Filter
	parent  *SidechainNode
	workSum *big.Int
}

// sidechainRootedTree represents a rooted tree of blocks not currently in the
// wallet's main chain.  If the parent of the root is not in the wallet's main
// chain, the root and all child blocks are orphans.
type sidechainRootedTree struct {
	root      *SidechainNode
	children  map[chainhash.Hash]*SidechainNode
	tips      map[chainhash.Hash]*SidechainNode
	bestChain []*SidechainNode // memoized
}

// newSideChainRootedTree creates a new rooted tree for a SidechainForest.  The
// root must either be the first block in a fork off the main chain, or an
// orphan block.
func newSideChainRootedTree(root *SidechainNode) *sidechainRootedTree {
	root.workSum = blockchain.CalcWork(root.Header.Bits)
	return &sidechainRootedTree{
		root:     root,
		children: make(map[chainhash.Hash]*SidechainNode),
		tips:     make(map[chainhash.Hash]*SidechainNode),
	}
}

// NewSidechainNode creates a block node for usage with a SidechainForest.
func NewSidechainNode(header *wire.BlockHeader, hash *chainhash.Hash, filter *gcs.Filter) *SidechainNode {
	return &SidechainNode{
		Header: header,
		Hash:   hash,
		Filter: filter,
	}
}

// duplicateNode checks if n, or another node which represents the same block,
// is already contained in the tree.
func (t *sidechainRootedTree) duplicateNode(n *SidechainNode) bool {
	if *t.root.Hash == *n.Hash {
		return true
	}
	_, ok := t.children[*n.Hash]
	return ok
}

// maybeAttachNode checks whether the node is a child of any node in the rooted
// tree.  If so, the child is added to the tree and true is returned.  This
// function does not check for duplicate nodes and must only be called on nodes
// known to not already exist in the tree.
func (t *sidechainRootedTree) maybeAttachNode(n *SidechainNode) bool {
	if *t.root.Hash == n.Header.PrevBlock && n.Header.Height == t.root.Header.Height+1 {
		n.parent = t.root
		t.children[*n.Hash] = n
		t.tips[*n.Hash] = n
		n.workSum = new(big.Int).Add(n.parent.workSum, blockchain.CalcWork(n.Header.Bits))
		t.bestChain = nil
		return true
	}
	if parent, ok := t.children[n.Header.PrevBlock]; ok && n.Header.Height == parent.Header.Height+1 {
		n.parent = parent
		t.children[*n.Hash] = n
		t.tips[*n.Hash] = n
		delete(t.tips, *parent.Hash)
		n.workSum = new(big.Int).Add(n.parent.workSum, blockchain.CalcWork(n.Header.Bits))
		t.bestChain = nil
		return true
	}
	return false
}

// bestSideChain returns one of the best sidechains in the tree, starting with
// the root and sorted in increasing order of block heights, along with the
// summed work of blocks in the sidechain including the root.  If there are
// multiple best chain candidates, the chosen chain is indeterminate.
func (t *sidechainRootedTree) bestSideChain() ([]*SidechainNode, *big.Int) {
	// Return memoized best chain if unchanged.
	if len(t.bestChain) != 0 {
		return t.bestChain, t.bestChain[len(t.bestChain)-1].workSum
	}

	// Find a tip block, if any, with the largest total work sum (relative to
	// this tree).
	var best *SidechainNode
	for _, n := range t.tips {
		if best == nil || best.workSum.Cmp(n.workSum) == -1 {
			best = n
		}
	}

	// If only the root exists in this tree, the entire sidechain is only one
	// block long.
	if best == nil {
		t.bestChain = []*SidechainNode{t.root}
		return t.bestChain, t.root.workSum
	}

	// Create the sidechain by iterating the chain in reverse starting with the
	// tip.
	chain := make([]*SidechainNode, best.Header.Height-t.root.Header.Height)
	n := best
	for i, j := 0, len(chain)-1; i < len(chain); i, j = i+1, j-1 {
		chain[j] = n
		n = n.parent
	}

	// Memoize the best chain for future calls.  This value remains cached until
	// a new node is added to the tree.
	t.bestChain = chain

	return chain, best.workSum
}

// AddBlockNode adds a sidechain block node to the forest.  The node may either
// begin a new sidechain, extend an existing sidechain, or start or extend a
// tree of orphan blocks.  Adding the parent node of a previously-saved orphan
// block will restructure the forest by re-rooting the previous orphan tree onto
// the tree containing the added node.
func (f *SidechainForest) AddBlockNode(n *SidechainNode) {
	// Add the node to an existing tree if it is a direct child of any recorded
	// blocks, or create a new tree containing only the node as the root.
	var nodeTree *sidechainRootedTree
	for _, t := range f.trees {
		// Avoid adding the node if it represents the same block already in the
		// tree.  This keeps previous-parent consistency in the case that this
		// node has a different memory address than the existing node, and
		// prevents adding a duplicate block as a new root in the forest.
		if t.duplicateNode(n) {
			return
		}

		if t.maybeAttachNode(n) {
			nodeTree = t
			break
		}
	}
	if nodeTree == nil {
		nodeTree = newSideChainRootedTree(n)
		f.trees = append(f.trees, nodeTree)
	}

	// Search for any trees whose root references the added node as a parent.
	// These trees, which were previously orphans, are now children of nodeTree.
	// The forest is kept disjoint by attaching all nodes of the previous orphan
	// tree to nodeTree and removing the old tree.
	for i := 0; i < len(f.trees); {
		orphanTree := f.trees[i]
		if orphanTree.root.Header.PrevBlock != *n.Hash {
			i++
			continue
		}

		// The previous orphan tree must be combined with the extended side
		// chain tree and removed from the forest.  All nodes from the old
		// orphan tree are dumped to a single slice, sorted by block height, and
		// then reattached to the extended tree.  A failure to add any of these
		// side chain nodes indicates an internal consistency error and the
		// algorithm will panic.
		var nodes []*SidechainNode
		nodes = append(nodes, orphanTree.root)
		for _, node := range orphanTree.children {
			nodes = append(nodes, node)
		}
		sort.Slice(nodes, func(i, j int) bool {
			return nodes[i].Header.Height < nodes[j].Header.Height
		})
		for _, n := range nodes {
			if nodeTree.duplicateNode(n) || !nodeTree.maybeAttachNode(n) {
				panic("sidechain forest internal consistency error")
			}
		}
		f.trees[i] = f.trees[len(f.trees)-1]
		f.trees[len(f.trees)-1] = nil
		f.trees = f.trees[:len(f.trees)-1]
	}
}

// Prune removes any sidechain trees which contain a root that is significantly
// behind the current main chain tip block.
func (f *SidechainForest) Prune(mainChainHeight int32, params *chaincfg.Params) {
	pruneDepth := int32(params.CoinbaseMaturity)
	for i := 0; i < len(f.trees); {
		if int32(f.trees[i].root.Header.Height)+pruneDepth < mainChainHeight {
			f.trees[i] = f.trees[len(f.trees)-1]
			f.trees[len(f.trees)-1] = nil
			f.trees = f.trees[:len(f.trees)-1]
		} else {
			i++
		}
	}
}

// PruneTree removes the tree beginning with root from the forest.
func (f *SidechainForest) PruneTree(root *chainhash.Hash) {
	for i, tree := range f.trees {
		if *root == *tree.root.Hash {
			f.trees[i] = f.trees[len(f.trees)-1]
			f.trees[len(f.trees)-1] = nil
			f.trees = f.trees[:len(f.trees)-1]
			return
		}
	}
}

// EvaluateBestChain checks if any of the sidechain trees that are not (or are
// no longer) orphans create a better chain than the wallet's current main
// chain, returning nodes of the new best chain if so.  This may be an extension
// of the main chain or require a reorg.  If the main chain does not need to
// change but an error did not otherwise occur, (nil, nil) is returned.
func (w *Wallet) EvaluateBestChain(forest *SidechainForest) ([]*SidechainNode, error) {
	var newBestChain []*SidechainNode
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		// TODO: see comment below about using work
		ns := dbtx.ReadBucket(wtxmgrNamespaceKey)
		_, bestChainHeight := w.TxStore.MainChainTip(ns)

		for _, t := range forest.trees {
			// The root's parent must be part of the wallet's main chain,
			// otherwise this tree only contains orphans blocks.
			inMainChain, _ := w.TxStore.BlockInMainChain(dbtx, &t.root.Header.PrevBlock)
			if !inMainChain {
				continue
			}

			// TODO: instead of finding the best chain by comparing block
			// heights, this must compare the total work.  Since we have already
			// calculated the total work performed by the sidechain, compare
			// this to the sum of work in the main chain since the fork point.
			chain, _ := t.bestSideChain()
			if int32(chain[len(chain)-1].Header.Height) > bestChainHeight {
				newBestChain = chain
				bestChainHeight = int32(chain[len(chain)-1].Header.Height)
			}
		}
		return nil
	})
	return newBestChain, err
}
