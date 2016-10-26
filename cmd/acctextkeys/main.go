// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/golangcrypto/ssh/terminal"
	"github.com/jessevdk/go-flags"
)

// Namespace keys.
var (
	waddrmgrNamespaceKey = []byte("waddrmgr")
)

// Flags.
var opts = struct {
	Account          string `long:"account" description:"Account name"`
	AppDataDir       string `long:"appdata" description:"Wallet application data directory"`
	PublicPassphrase string `long:"pubpassphrase" description:"Wallet public data encryption passhprase"`
	SimNet           bool   `long:"simnet" description:"Use the simulation testing network"`
	TestNet3         bool   `long:"testnet3" description:"Use the test network (version 3)"`
}{
	Account:          "default",
	AppDataDir:       btcutil.AppDataDir("btcwallet", false),
	PublicPassphrase: wallet.InsecurePubPassphrase,
	SimNet:           false,
	TestNet3:         false,
}

func init() {
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}
}

func main() {
	os.Exit(mainInt())
}

func mainInt() int {
	netParams := &chaincfg.MainNetParams
	netName := "mainnet"
	netSets := 0
	if opts.TestNet3 {
		netParams = &chaincfg.TestNet3Params
		netName = "testnet"
		netSets++
	}
	if opts.SimNet {
		netParams = &chaincfg.SimNetParams
		netName = "simnet"
		netSets++
	}
	if netSets > 1 {
		fmt.Fprintln(os.Stderr, "Multiple networks selected -- pick one")
		return 1
	}

	pubPass := []byte(opts.PublicPassphrase)
	for opts.PublicPassphrase == wallet.InsecurePubPassphrase || opts.PublicPassphrase == "" {
		fmt.Print("Prompt for public encryption passphrase? [y/N] ")

		scanner := bufio.NewScanner(bufio.NewReader(os.Stdin))
		if !scanner.Scan() {
			// Exit on EOF
			return 0
		}
		err := scanner.Err()
		if err != nil {
			fmt.Println()
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		resp := scanner.Text()
		switch {
		default:
			fmt.Println("Enter yes or no.")
			continue
		case yes(resp):
			pubPass, err = promptSecret("Public passphrase")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
		case no(resp), resp == "":
		}
		break
	}

	dbPath := filepath.Join(opts.AppDataDir, netName, "wallet.db")
	fmt.Println("Database path:", dbPath)
	_, err := os.Stat(dbPath)
	if os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "Database file does not exist")
		return 1
	}

	db, err := walletdb.Open("bdb", dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open database:", err)
		return 1
	}
	defer db.Close()

	ns, err := db.Namespace(waddrmgrNamespaceKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	m, err := waddrmgr.Open(ns, pubPass, netParams, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open address manager:", err)
		return 1
	}

	account, err := m.LookupAccount(opts.Account)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	acctExtendedPubKey, err := m.AccountExtendedPubKey(account)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	externalBranchExtendedPubKey, err := acctExtendedPubKey.Child(0) // acct'/0
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to derive external branch pubkey:", err)
		return 1
	}

	fmt.Printf("Extended pubkeys for account %d (%s):\n", account, opts.Account)
	fmt.Printf("Account hardened extended pubkey: %s\n", acctExtendedPubKey.String())
	fmt.Printf("External branch extended pubkey:  %s\n", externalBranchExtendedPubKey.String())
	return 0
}

func yes(s string) bool {
	switch s {
	case "y", "Y", "yes", "Yes":
		return true
	default:
		return false
	}
}

func no(s string) bool {
	switch s {
	case "n", "N", "no", "No":
		return true
	default:
		return false
	}
}

func promptSecret(what string) ([]byte, error) {
	fmt.Printf("%s: ", what)
	fd := int(os.Stdin.Fd())
	input, err := terminal.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return nil, err
	}
	return input, nil
}
