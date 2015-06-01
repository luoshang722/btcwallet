package wallet

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/internal/prompt"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

const (
	walletDbName = "wallet.db"
)

var (
	ErrLoaded = errors.New("wallet already loaded")
	ErrExists = errors.New("wallet already exists")
)

// Loader implements the creating of new and opening of existing wallets, while
// providing a callback system for other subsystems to handle the loading of a
// wallet.  This is primarely intended for use by the RPC servers, to enable
// methods and services which require the wallet when the wallet is loaded by
// another subsystem.
//
// Loader is safe for concurrent access.
type Loader struct {
	callbacks   []func(*Wallet, walletdb.DB)
	chainParams *chaincfg.Params
	dbDirPath   string
	wallet      *Wallet
	db          walletdb.DB
	mu          sync.Mutex
}

func NewLoader(chainParams *chaincfg.Params, dbDirPath string) *Loader {
	return &Loader{
		chainParams: chainParams,
		dbDirPath:   dbDirPath,
	}
}

func (l *Loader) GetOrAddCallback(fn func(*Wallet, walletdb.DB)) (w *Wallet, db walletdb.DB, ok bool) {
	l.mu.Lock()

	w = l.wallet
	db = l.db
	ok = l.wallet != nil

	if !ok {
		l.callbacks = append(l.callbacks, fn)
	}

	l.mu.Unlock()

	return
}

// Executes each added callback and prevents loader from loading any additional
// wallets.  Requires mutex to be locked.
func (l *Loader) onLoaded(w *Wallet, db walletdb.DB) {
	for _, fn := range l.callbacks {
		fn(w, db)
	}

	l.wallet = w
	l.db = db
	l.callbacks = nil // not needed anymore
}

// RunAfterLoad adds a function to be executed when the loader creates or opens
// a wallet.  Functions are executed in a single goroutine in the order they are
// added.
func (l *Loader) RunAfterLoad(fn func(*Wallet, walletdb.DB)) {
	l.mu.Lock()
	if l.wallet != nil {
		w := l.wallet
		db := l.db
		l.mu.Unlock()
		fn(w, db)
	} else {
		l.callbacks = append(l.callbacks, fn)
		l.mu.Unlock()
	}
}

// CreateNewWallet creates a new wallet using the provided public and private
// passphrases.  The seed is optional.  If non-nil, addresses are derived from
// this seed.  If nil, a secure random seed is generated.
func (l *Loader) CreateNewWallet(pubPassphrase, privPassphrase, seed []byte) (*Wallet, error) {
	defer l.mu.Unlock()
	l.mu.Lock()

	if l.wallet != nil {
		return nil, ErrLoaded
	}

	dbPath := filepath.Join(l.dbDirPath, walletDbName)
	exists, err := fileExists(dbPath)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrExists
	}

	// Create the wallet database backed by bolt db.
	err = os.MkdirAll(l.dbDirPath, 0700)
	if err != nil {
		return nil, err
	}
	db, err := walletdb.Create("bdb", dbPath)
	if err != nil {
		return nil, err
	}

	// Create the address manager.
	addrMgrNamespace, err := db.Namespace(waddrmgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	_, err = waddrmgr.Create(addrMgrNamespace, seed, pubPassphrase,
		privPassphrase, l.chainParams, nil)
	if err != nil {
		return nil, err
	}

	// Create empty transaction manager.
	txMgrNamespace, err := db.Namespace(wtxmgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	_, err = wtxmgr.Create(txMgrNamespace)
	if err != nil {
		return nil, err
	}

	// Open the newly-created wallet.
	w, err := Open(pubPassphrase, l.chainParams, db, addrMgrNamespace, txMgrNamespace, nil)
	if err != nil {
		return nil, err
	}

	l.onLoaded(w, db)
	return w, nil
}

var noConsoleErr = errors.New("db upgrade requires console access for additional input")

func noConsole() ([]byte, error) {
	return nil, noConsoleErr
}

func (l *Loader) OpenExistingWallet(pubPassphrase []byte, canConsolePrompt bool) (*Wallet, error) {
	defer l.mu.Unlock()
	l.mu.Lock()

	if l.wallet != nil {
		return nil, ErrLoaded
	}

	// Ensure that the network directory exists.
	if err := checkCreateDir(l.dbDirPath); err != nil {
		return nil, err
	}

	// Open the database using the boltdb backend.
	dbPath := filepath.Join(l.dbDirPath, walletDbName)
	db, err := walletdb.Open("bdb", dbPath)
	if err != nil {
		log.Errorf("Failed to open database: %v", err)
		return nil, err
	}

	addrMgrNS, err := db.Namespace(waddrmgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	txMgrNS, err := db.Namespace(wtxmgrNamespaceKey)
	if err != nil {
		return nil, err
	}
	var cbs *waddrmgr.OpenCallbacks
	if canConsolePrompt {
		cbs = &waddrmgr.OpenCallbacks{
			ObtainSeed:        prompt.ProvideSeed,
			ObtainPrivatePass: prompt.ProvidePrivPassphrase,
		}
	} else {
		cbs = &waddrmgr.OpenCallbacks{
			ObtainSeed:        noConsole,
			ObtainPrivatePass: noConsole,
		}
	}
	w, err := Open(pubPassphrase, l.chainParams, db, addrMgrNS, txMgrNS, cbs)
	if err != nil {
		return nil, err
	}
	w.Start()

	l.onLoaded(w, db)
	return w, nil
}

func (l *Loader) WalletExists() (bool, error) {
	dbPath := filepath.Join(l.dbDirPath, walletDbName)
	return fileExists(dbPath)
}

func (l *Loader) LoadedWallet() (*Wallet, bool) {
	l.mu.Lock()
	w := l.wallet
	l.mu.Unlock()
	return w, w != nil
}

func fileExists(filePath string) (bool, error) {
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
