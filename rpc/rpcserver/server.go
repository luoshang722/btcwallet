package rpcserver

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/internal/cfgutil"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/netparams"
	pb "github.com/btcsuite/btcwallet/rpc/walletrpc"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
)

// translateError attempts to create a new gRPC error with an appropiate error
// code for recognized errors.  If this can not be done, the original error is
// returned.
//
// This function is by no means complete and should be expanded based on other
// known errors.  Any RPC handler not returning a gRPC error (with grpc.Errorf)
// should return this result instead.
func translateError(err error) error {
	switch {
	case waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase):
		return grpc.Errorf(codes.InvalidArgument, "%s", err.Error())
	default:
		return err
	}
}

// Server provides wallet services for RPC clients.
type Server struct {
	wallet *wallet.Wallet
}

// LoaderServer provides RPC clients with the ability to load and close wallets,
// as well as establishing a RPC connection to a btcd consensus server.
type LoaderServer struct {
	loader    *wallet.Loader
	activeNet *netparams.Params
	rpcClient *chain.RPCClient
	mu        sync.Mutex
}

var (
	_ pb.WalletServiceServer       = (*Server)(nil)
	_ pb.WalletLoaderServiceServer = (*LoaderServer)(nil)
)

func NewServer(wallet *wallet.Wallet) *Server {
	return &Server{wallet}
}

func (s *Server) Ping(cxt context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{}, nil
}

func (s *Server) Network(cxt context.Context, req *pb.NetworkRequest) (*pb.NetworkResponse, error) {
	return &pb.NetworkResponse{ActiveNetwork: uint32(s.wallet.ChainParams().Net)}, nil
}

func (s *Server) AccountNumber(cxt context.Context, req *pb.AccountNumberRequest) (*pb.AccountNumberResponse, error) {
	return &pb.AccountNumberResponse{AccountNumber: 123}, nil
}

func (s *Server) Accounts(cxt context.Context, req *pb.AccountsRequest) (*pb.AccountsResponse, error) {
	resp, err := s.wallet.Accounts()
	if err != nil {
		return nil, translateError(err)
	}
	accounts := make([]*pb.AccountsResponse_Account, len(resp.Accounts))
	for i := range resp.Accounts {
		a := &resp.Accounts[i]
		accounts[i] = &pb.AccountsResponse_Account{
			AccountNumber: a.AccountNumber,
			AccountName:   a.AccountName,
			TotalBalance:  int64(a.TotalBalance),
		}
	}
	return &pb.AccountsResponse{
		Accounts:           accounts,
		CurrentBlockHash:   resp.CurrentBlockHash[:],
		CurrentBlockHeight: resp.CurrentBlockHeight,
	}, nil
}

func (s *Server) RenameAccount(cxt context.Context, req *pb.RenameAccountRequest) (*pb.RenameAccountResponse, error) {
	err := s.wallet.RenameAccount(req.AccountNumber, req.NewName)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.RenameAccountResponse{}, nil
}

func (s *Server) NextAccount(cxt context.Context, req *pb.NextAccountRequest) (*pb.NextAccountResponse, error) {
	defer zero.Bytes(req.Passphrase)

	if req.AccountName == "" {
		return nil, grpc.Errorf(codes.InvalidArgument, "account name may not be empty")
	}

	lock := make(chan time.Time, 1)
	defer func() {
		lock <- time.Time{} // send matters, not the value
	}()
	err := s.wallet.Unlock(req.Passphrase, lock)
	if err != nil {
		return nil, translateError(err)
	}

	account, err := s.wallet.NextAccount(req.AccountName)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.NextAccountResponse{AccountNumber: account}, nil
}

func (s *Server) NextAddress(cxt context.Context, req *pb.NextAddressRequest) (*pb.NextAddressResponse, error) {
	addr, err := s.wallet.NewAddress(req.Account)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.NextAddressResponse{Address: addr.EncodeAddress()}, nil
}

func (s *Server) ImportPrivateKey(cxt context.Context, req *pb.ImportPrivateKeyRequest) (*pb.ImportPrivateKeyResponse, error) {
	defer zero.Bytes(req.Passphrase)

	return &pb.ImportPrivateKeyResponse{}, nil
}

func (s *Server) Balance(cxt context.Context, req *pb.BalanceRequest) (*pb.BalanceResponse, error) {
	reqConfs := req.RequiredConfirmations
	// TODO: fetch these under a single db tx.
	total, err := s.wallet.CalculateAccountBalance(0, 0)
	if err != nil {
		return nil, translateError(err)
	}
	spendable, err := s.wallet.CalculateAccountBalance(0, reqConfs)
	if err != nil {
		return nil, translateError(err)
	}

	var immatureReward int64 // TODO

	// TODO: Spendable currently includes multisig outputs that may not
	// actually be spendable without additional keys.
	return &pb.BalanceResponse{Total: int64(total), Spendable: int64(spendable), ImmatureReward: immatureReward}, nil
}

// confirmed checks whether a transaction at height txHeight has met minconf
// confirmations for a blockchain at height curHeight.
func confirmed(minconf, txHeight, curHeight int32) bool {
	return confirms(txHeight, curHeight) >= minconf
}

// confirms returns the number of confirmations for a transaction in a block at
// height txHeight (or -1 for an unconfirmed tx) given the chain height
// curHeight.
func confirms(txHeight, curHeight int32) int32 {
	switch {
	case txHeight == -1, txHeight > curHeight:
		return 0
	default:
		return curHeight - txHeight + 1
	}
}

func (s *Server) SelectUnspentOutputs(cxt context.Context, req *pb.SelectUnspentOutputsRequest) (*pb.SelectUnspentOutputsResponse, error) {
	// TODO: A predicate function for selecting outputs should be created and passed to
	// a database view of just a particular account's utxos to prevent reading every
	// unspent transaction output from every account into memory at once.

	syncBlock := s.wallet.Manager.SyncedTo()

	outputs, err := s.wallet.TxStore.UnspentOutputs()
	if err != nil {
		return nil, translateError(err)
	}

	selectedOutputs := make([]*pb.SelectUnspentOutputsResponse_Output, 0, len(outputs))
	var totalAmount btcutil.Amount
	for i := range outputs {
		output := &outputs[i]

		if !confirmed(req.RequiredConfirmations, output.Height, syncBlock.Height) {
			continue
		}
		if !req.IncludeImmatureCoinbases && output.FromCoinBase &&
			!confirmed(blockchain.CoinbaseMaturity, output.Height, syncBlock.Height) {
			continue
		}

		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, s.wallet.ChainParams())
		if err != nil || len(addrs) == 0 {
			// Cannot determine which account this belongs to
			// without a valid address.  Fix this by saving
			// outputs per account (per-account wtxmgr).
			continue
		}
		outputAcct, err := s.wallet.Manager.AddrAccount(addrs[0])
		if err != nil {
			return nil, translateError(err)
		}
		if outputAcct != req.Account {
			continue
		}

		selectedOutputs = append(selectedOutputs, &pb.SelectUnspentOutputsResponse_Output{
			TransactionHash: output.OutPoint.Hash[:],
			OutputIndex:     output.Index,
			Amount:          int64(output.Amount),
			PkScript:        output.PkScript,
			ReceiveTime:     output.Received.Unix(),
			FromCoinbase:    output.FromCoinBase,
		})
		totalAmount += output.Amount

		if req.TargetAmount != 0 && totalAmount > btcutil.Amount(req.TargetAmount) {
			break
		}

	}

	if req.TargetAmount != 0 && totalAmount < btcutil.Amount(req.TargetAmount) {
		return nil, errors.New("insufficient output value to reach target")
	}

	return &pb.SelectUnspentOutputsResponse{
		Outputs:     selectedOutputs,
		TotalAmount: int64(totalAmount),
	}, nil
}

func marshalGetTransactionsResult(wresp *wallet.GetTransactionsResult) (*pb.GetTransactionsResponse, error) {
	resp := pb.GetTransactionsResponse{
		MinedTransactions:   marshalBlocks(wresp.MinedTransactions),
		UnminedTransactions: marshalTransactionDetails(wresp.UnminedTransactions),
	}
	return &resp, nil
}

func (s *Server) GetTransactions(cxt context.Context, req *pb.GetTransactionsRequest) (resp *pb.GetTransactionsResponse, err error) {
	var startBlock, endBlock *wallet.BlockIdentifier
	if req.StartingBlockHash != nil && req.StartingBlockHeight != 0 {
		return nil, errors.New("starting block hash and height may not be specified simultaneously")
	} else if req.StartingBlockHash != nil {
		startBlockHash, err := wire.NewShaHash(req.StartingBlockHash)
		if err != nil {
			return nil, grpc.Errorf(codes.InvalidArgument, "%s", err.Error())
		}
		startBlock = wallet.NewBlockIdentifierFromHash(startBlockHash)
	} else if req.StartingBlockHeight != 0 {
		startBlock = wallet.NewBlockIdentifierFromHeight(req.StartingBlockHeight)
	}

	if req.EndingBlockHash != nil && req.EndingBlockHeight != 0 {
		return nil, grpc.Errorf(codes.InvalidArgument, "ending block hash and height may not be specified simultaneously")
	} else if req.EndingBlockHash != nil {
		endBlockHash, err := wire.NewShaHash(req.EndingBlockHash)
		if err != nil {
			return nil, grpc.Errorf(codes.InvalidArgument, "%s", err.Error())
		}
		endBlock = wallet.NewBlockIdentifierFromHash(endBlockHash)
	} else if req.EndingBlockHeight != 0 {
		endBlock = wallet.NewBlockIdentifierFromHeight(req.EndingBlockHeight)
	}

	var minRecentTxs int
	if req.MinimumRecentTransactions != 0 {
		if endBlock != nil {
			return nil, grpc.Errorf(codes.InvalidArgument, "ending block and minimum number of recent transactions may not be specified simultaneously")
		}
		minRecentTxs = int(req.MinimumRecentTransactions)
		if minRecentTxs < 0 {
			return nil, grpc.Errorf(codes.InvalidArgument, "minimum number of recent transactions may not be negative")
		}
	}

	// TODO: use minRecentTxs during fetch.
	_ = minRecentTxs

	gtr, err := s.wallet.GetTransactions(startBlock, endBlock, cxt.Done())
	if err != nil {
		return nil, translateError(err)
	}
	return marshalGetTransactionsResult(gtr)
}

func (s *Server) ChangePassphrase(cxt context.Context, req *pb.ChangePassphraseRequest) (*pb.ChangePassphraseResponse, error) {
	defer func() {
		zero.Bytes(req.OldPassphrase)
		zero.Bytes(req.NewPassphrase)
	}()

	err := s.wallet.Manager.ChangePassphrase(req.OldPassphrase, req.NewPassphrase,
		req.Key != pb.ChangePassphraseRequest_PUBLIC, &waddrmgr.DefaultScryptOptions)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.ChangePassphraseResponse{}, nil
}

func (s *Server) SignTransaction(cxt context.Context, req *pb.SignTransactionRequest) (*pb.SignTransactionResponse, error) {
	// TODO
	return &pb.SignTransactionResponse{}, nil
}

func (s *Server) CreateSignedTransaction(cxt context.Context, req *pb.CreateSignedTransactionRequest) (*pb.CreateSignedTransactionResponse, error) {
	defer zero.Bytes(req.Passphrase)

	if !req.RandomizeOutputOrder {
		// Current implementation uses map of address strings with key,
		// so order is lost.
		return nil, grpc.Errorf(codes.Unimplemented, "non-randomzied output order is not yet supported")
	}

	lock := make(chan time.Time, 1)
	defer func() {
		lock <- time.Time{} // send matters, not the value
	}()
	err := s.wallet.Unlock(req.Passphrase, lock)
	if err != nil {
		return nil, translateError(err)
	}

	// Lock holding shouldn't be necessary but the current design allows another
	// caller to forcible lock the wallet from under us.  This blocks that caller
	// until we finish.
	//
	// Currently commented out because CreateSimpleTx does this again and that
	// deadlocks.
	/*
		unlockGuard, err := s.wallet.HoldUnlock()
		if err != nil {
			return nil, err
		}
		defer fmt.Println("released hold")
		defer unlockGuard.Release()
		defer fmt.Println("releasing")
	*/

	// This is unfortunately the only function the wallet package exposes to
	// create a signed transaction.  Later this should fund a partially
	// created transaction with unspent outputs and sign it, and it should
	// only deal with raw outputs, not addresses.
	pairs := make(map[string]btcutil.Amount)
	for _, output := range req.Outputs {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript, s.wallet.ChainParams())
		if err != nil || len(addrs) != 1 {
			return nil, grpc.Errorf(codes.Unimplemented, "non-address scripts are unimplemented")
		}
		encodedAddr := addrs[0].EncodeAddress()
		if _, ok := pairs[encodedAddr]; ok {
			return nil, grpc.Errorf(codes.Unimplemented, "duplicate address outputs are unimplemented")
		}
		pairs[encodedAddr] = btcutil.Amount(output.Amount)
	}
	createdTx, err := s.wallet.CreateSimpleTx(req.Account, pairs, req.RequiredConfirmations)
	if err != nil {
		return nil, translateError(err)
	}

	var serializedTransaction bytes.Buffer
	err = createdTx.MsgTx.Serialize(&serializedTransaction)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.CreateSignedTransactionResponse{
		Transaction: serializedTransaction.Bytes(),
		Fee:         int64(createdTx.Fee),
	}, nil
}

func (s *Server) PublishTransaction(cxt context.Context, req *pb.PublishTransactionRequest) (*pb.PublishTransactionResponse, error) {
	var msgTx wire.MsgTx
	err := msgTx.Deserialize(bytes.NewReader(req.SignedTransaction))
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	err = s.wallet.PublishTransaction(&msgTx)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.PublishTransactionResponse{}, nil
}

func marshalTransactionInputs(v []wallet.TransactionSummaryInput) []*pb.TransactionDetails_Input {
	inputs := make([]*pb.TransactionDetails_Input, len(v))
	for i := range v {
		input := &v[i]
		inputs[i] = &pb.TransactionDetails_Input{
			Index:           input.Index,
			PreviousAccount: input.PreviousAccount,
			PreviousAmount:  int64(input.PreviousAmount),
		}
	}
	return inputs
}

func marshalTransactionOutputs(v []wallet.TransactionSummaryOutput) []*pb.TransactionDetails_Output {
	outputs := make([]*pb.TransactionDetails_Output, len(v))
	for i := range v {
		output := &v[i]

		var addresses []string
		if len(output.Addresses) != 0 {
			addresses = make([]string, 0, len(output.Addresses))
			for _, a := range output.Addresses {
				addresses = append(addresses, a.EncodeAddress())
			}
		}

		outputs[i] = &pb.TransactionDetails_Output{
			Index:     output.Index,
			Amount:    int64(output.Amount),
			Mine:      output.Mine,
			Account:   output.Account,
			Internal:  output.Internal,
			Addresses: addresses,
		}
	}
	return outputs
}

func marshalTransactionDetails(v []wallet.TransactionSummary) []*pb.TransactionDetails {
	txs := make([]*pb.TransactionDetails, len(v))
	for i := range v {
		tx := &v[i]
		txs[i] = &pb.TransactionDetails{
			Hash:        tx.Hash[:],
			Transaction: tx.Transaction,
			Debits:      marshalTransactionInputs(tx.MyInputs),
			Outputs:     marshalTransactionOutputs(tx.MyOutputs),
			Fee:         int64(tx.Fee),
			Timestamp:   tx.Timestamp,
		}
	}
	return txs
}

func marshalBlocks(v []wallet.Block) []*pb.BlockDetails {
	blocks := make([]*pb.BlockDetails, len(v))
	for i := range v {
		block := &v[i]
		blocks[i] = &pb.BlockDetails{
			Hash:         block.Hash[:],
			Height:       block.Height,
			Timestamp:    block.Timestamp,
			Transactions: marshalTransactionDetails(block.Transactions),
		}
	}
	return blocks
}

func marshalHashes(v []*wire.ShaHash) [][]byte {
	hashes := make([][]byte, len(v))
	for i, hash := range v {
		hashes[i] = hash[:]
	}
	return hashes
}

func marshalAccountBalances(v []wallet.AccountBalance) []*pb.AccountBalance {
	balances := make([]*pb.AccountBalance, len(v))
	for i := range v {
		balance := &v[i]
		balances[i] = &pb.AccountBalance{
			Account:      balance.Account,
			TotalBalance: int64(balance.TotalBalance),
		}
	}
	return balances
}

func (s *Server) TransactionNotifications(req *pb.TransactionNotificationsRequest, svr pb.WalletService_TransactionNotificationsServer) error {
	n := s.wallet.NtfnServer.TransactionNotifications()
	defer n.Done()

	cxtDone := svr.Context().Done()
	for {
		select {
		case v := <-n.C:
			resp := pb.TransactionNotificationsResponse{
				AttachedBlocks:           marshalBlocks(v.AttachedBlocks),
				DetachedBlocks:           marshalHashes(v.DetachedBlocks),
				UnminedTransactions:      marshalTransactionDetails(v.UnminedTransactions),
				UnminedTransactionHashes: marshalHashes(v.UnminedTransactionHashes),
				NewBalances:              marshalAccountBalances(v.NewBalances),
			}
			err := svr.Send(&resp)
			if err != nil {
				return translateError(err)
			}

		case <-cxtDone:
			return nil
		}
	}
}

func (s *Server) SpentnessNotifications(req *pb.SpentnessNotificationsRequest, svr pb.WalletService_SpentnessNotificationsServer) error {
	n := s.wallet.NtfnServer.AccountSpentnessNotifications(req.Account)
	defer n.Done()

	cxtDone := svr.Context().Done()
	for {
		select {
		case v := <-n.C:
			index := v.Index()
			resp := pb.SpentnessNotificationsResponse{
				Hash:  v.Hash()[:],
				Index: index,
			}
			spenderHash, spenderIndex, ok := v.Spender()
			if ok {
				resp.Spender = &pb.SpentnessNotificationsResponse_Spender{
					Hash:  spenderHash[:],
					Index: spenderIndex,
				}
			}
			err := svr.Send(&resp)
			if err != nil {
				return translateError(err)
			}

		case <-cxtDone:
			return nil
		}
	}
}

func (s *Server) AccountNotifications(req *pb.AccountNotificationsRequest, svr pb.WalletService_AccountNotificationsServer) error {
	n := s.wallet.NtfnServer.AccountNotifications()
	defer n.Done()

	cxtDone := svr.Context().Done()
	for {
		select {
		case v := <-n.C:
			resp := pb.AccountNotificationsResponse{
				AccountNumber:    v.AccountNumber,
				AccountName:      v.AccountName,
				ExternalKeyCount: v.ExternalKeyCount,
				InternalKeyCount: v.InternalKeyCount,
				ImportedKeyCount: v.ImportedKeyCount,
			}
			err := svr.Send(&resp)
			if err != nil {
				return translateError(err)
			}

		case <-cxtDone:
			return nil
		}
	}
}

func NewLoaderServer(loader *wallet.Loader, activeNet *netparams.Params) *LoaderServer {
	return &LoaderServer{loader: loader, activeNet: activeNet}
}

func (s *LoaderServer) CreateWallet(cxt context.Context, req *pb.CreateWalletRequest) (*pb.CreateWalletResponse, error) {
	defer func() {
		zero.Bytes(req.PrivatePassphrase)
		zero.Bytes(req.Seed)
	}()

	wallet, err := s.loader.CreateNewWallet(req.PublicPassphrase, req.PrivatePassphrase, req.Seed)
	if err != nil {
		return nil, translateError(err)
	}

	s.mu.Lock()
	if s.rpcClient != nil {
		wallet.SynchronizeRPC(s.rpcClient)
	}
	s.mu.Unlock()

	return &pb.CreateWalletResponse{}, nil
}

func (s *LoaderServer) OpenWallet(cxt context.Context, req *pb.OpenWalletRequest) (*pb.OpenWalletResponse, error) {
	wallet, err := s.loader.OpenExistingWallet(req.PublicPassphrase, false)
	if err != nil {
		fmt.Println(err)
		return nil, translateError(err)
	}

	s.mu.Lock()
	if s.rpcClient != nil {
		wallet.SynchronizeRPC(s.rpcClient)
	}
	s.mu.Unlock()

	return &pb.OpenWalletResponse{}, nil
}

func (s *LoaderServer) WalletExists(cxt context.Context, req *pb.WalletExistsRequest) (*pb.WalletExistsResponse, error) {
	exists, err := s.loader.WalletExists()
	if err != nil {
		return nil, translateError(err)
	}
	return &pb.WalletExistsResponse{Exists: exists}, nil
}

func (s *LoaderServer) CloseWallet(cxt context.Context, req *pb.CloseWalletRequest) (*pb.CloseWalletResponse, error) {
	loadedWallet, ok := s.loader.LoadedWallet()
	if !ok {
		return nil, grpc.Errorf(codes.FailedPrecondition, "wallet is not loaded")
	}

	loadedWallet.Stop()
	loadedWallet.WaitForShutdown()

	return &pb.CloseWalletResponse{}, nil
}

func (s *LoaderServer) StartBtcdRpc(cxt context.Context, req *pb.StartBtcdRpcRequest) (*pb.StartBtcdRpcResponse, error) {
	defer zero.Bytes(req.Password)

	networkAddress, err := cfgutil.NormalizeAddress(req.NetworkAddress, s.activeNet.RPCClientPort)
	if err != nil {
		return nil, translateError(err)
	}

	defer s.mu.Unlock()
	s.mu.Lock()

	if s.rpcClient != nil {
		return nil, grpc.Errorf(codes.FailedPrecondition, "RPC client already created")
	}

	// Error if the wallet is already syncing with the network.
	wallet, walletLoaded := s.loader.LoadedWallet()
	if walletLoaded && wallet.SynchronizingToNetwork() {
		return nil, grpc.Errorf(codes.FailedPrecondition, "wallet is loaded and already synchronizing")
	}

	rpcClient, err := chain.NewRPCClient(s.activeNet.Params, networkAddress, req.Username,
		string(req.Password), req.Certificate, len(req.Certificate) == 0, 1)
	if err != nil {
		return nil, translateError(err)
	}

	err = rpcClient.Start()
	if err != nil {
		return nil, grpc.Errorf(codes.Unavailable, "Connection to RPC server failed: %v", err)
	}

	s.rpcClient = rpcClient

	if walletLoaded {
		wallet.SynchronizeRPC(rpcClient)
	}

	return &pb.StartBtcdRpcResponse{}, nil
}
