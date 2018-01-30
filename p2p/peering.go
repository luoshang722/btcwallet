// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package p2p

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decred/dcrd/addrmgr"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/connmgr"
	"github.com/decred/dcrd/gcs"
	"github.com/decred/dcrd/gcs/blockcf"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrwallet/lru"
	"github.com/decred/dcrwallet/version"
	"golang.org/x/sync/errgroup"
)

// uaName is the LocalPeer useragent name.
const uaName = "dcrwallet"

// uaVersion is the LocalPeer useragent version.
var uaVersion = version.String()

// Pver is the maximum protocol version implemented by the LocalPeer.
const Pver = wire.NodeCFVersion

const maxOutboundConns = 8

// connectTimeout is the amount of time allowed before connecting, peering
// handshake, and protocol negotiation is aborted.
const connectTimeout = 30 * time.Second

// stallTimeout is the amount of time allowed before a request to receive data
// that is known to exist at the RemotePeer times out with no matching reply.
const stallTimeout = 30 * time.Second

const banThreshold = 100

const invLRUSize = 5000

var (
	// ErrMaxOutboundPeers is an error describing a failure to add any more
	// outbound peers which would cause the total
	ErrMaxOutboundPeers = errors.New("max outbound peer limit reached")

	// ErrMissingServices is an error describing a failure to connect to a peer
	// due to missing required service flags in the received version message.
	ErrMissingServices = errors.New("missing required service flags")
)

// RemotePeer represents a remote peer that can send and receive wire protocol
// messages with the local peer.  RemotePeers must be created by dialing the
// peer's address with a LocalPeer.
type RemotePeer struct {
	id       uint64
	lp       *LocalPeer
	ua       string
	services wire.ServiceFlag
	pver     uint32
	raddr    net.Addr
	na       *wire.NetAddress

	// io
	c       net.Conn
	mr      msgReader
	out     chan wire.Message
	outPrio chan wire.Message

	requestedBlocks   sync.Map // k=chainhash.Hash v=chan<- *wire.MsgBlock
	requestedCFilters sync.Map // k=chainhash.Hash v=chan<- *wire.MsgCFilter

	// headers message management.  Headers can either be fetched synchronously
	// or used to push block notifications with sendheaders.
	requestedHeaders   chan<- *wire.MsgHeaders // non-nil result chan when synchronous getheaders in process
	sendheaders        bool                    // whether a sendheaders message was sent
	requestedHeadersMu sync.Mutex

	invsSent lru.Cache // Hashes from sent inventory messages
	invsRecv lru.Cache // Hashes of received inventory messages
	banScore connmgr.DynamicBanScore

	err  error         // Final error of disconnected peer
	errc chan struct{} // Closed after err is set
}

type connection struct {
	id         uint64
	attempts   int
	state      connState
	persistent bool
}

type connState int

const (
	connIdle connState = iota
	connDialing
	connHandshaking
	connPeering
)

// LocalPeer represents the local peer that can send and receive wire protocol
// messages with remote peers on the network.
type LocalPeer struct {
	// atomics
	atomicMask          uint64
	atomicPeerIDCounter uint64

	dialer net.Dialer

	receivedGetData  chan *inMsg
	receivedHeaders  chan *inMsg
	receivedInv      chan *inMsg
	announcedHeaders chan *inMsg

	nonceLRU    lru.Cache // Nonces from our own version messages, to avoid self connections.
	chainParams *chaincfg.Params
	extaddr     net.Addr
	amgr        *addrmgr.AddrManager

	rpByID  map[uint64]*RemotePeer
	rpConns map[uint64]*connection
	rpMu    sync.Mutex
}

// NewLocalPeer creates a LocalPeer that is externally reachable to remote peers
// through extaddr.
func NewLocalPeer(params *chaincfg.Params, extaddr *net.TCPAddr, amgr *addrmgr.AddrManager) *LocalPeer {
	lp := &LocalPeer{
		receivedGetData:  make(chan *inMsg),
		receivedHeaders:  make(chan *inMsg),
		receivedInv:      make(chan *inMsg),
		announcedHeaders: make(chan *inMsg),
		nonceLRU:         lru.NewCache(50),
		chainParams:      params,
		extaddr:          extaddr,
		amgr:             amgr,
		rpByID:           make(map[uint64]*RemotePeer),
		rpConns:          make(map[uint64]*connection),
	}
	return lp
}

func (lp *LocalPeer) newMsgVersion(pver uint32, extaddr net.Addr, c net.Conn) (*wire.MsgVersion, error) {
	la, err := wire.NewNetAddress(c.LocalAddr(), 0) // We provide no services
	if err != nil {
		return nil, err
	}
	ra, err := wire.NewNetAddress(c.RemoteAddr(), 0)
	if err != nil {
		return nil, err
	}
	nonce, err := wire.RandomUint64()
	if err != nil {
		return nil, err
	}
	lp.nonceLRU.Add(nonce)
	v := wire.NewMsgVersion(la, ra, nonce, 0)
	v.AddUserAgent(uaName, uaVersion)
	return v, nil
}

// ConnectOutbound establishes a connection to a remote peer by their remote TCP
// address.  The peer is serviced in the background until the context is
// cancelled, the RemotePeer disconnects, times out, misbehaves, or the
// LocalPeer disconnects all peers.
func (lp *LocalPeer) ConnectOutbound(ctx context.Context, addr string, reqSvcs wire.ServiceFlag) (*RemotePeer, error) {
	log.Infof("Attempting outbound connection to peer %v", addr)

	connectCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	// Generate a unique ID for this peer and add the initial connection state.
	id := atomic.AddUint64(&lp.atomicPeerIDCounter, 1)
	lp.rpMu.Lock()
	lp.rpConns[id] = &connection{
		id:         id,
		persistent: false,
	}
	lp.rpMu.Unlock()

	rp, err := lp.connectOutbound(connectCtx, id, addr)
	if err != nil {
		return nil, err
	}

	log.Infof("Connected to outbound peer %v", rp.raddr)

	go lp.serveUntilError(ctx, rp)

	var waitForAddrs <-chan time.Time
	if lp.amgr.NeedMoreAddresses() {
		waitForAddrs = time.After(stallTimeout)
		err = rp.GetAddrs(ctx)
		if err != nil {
			return nil, err
		}
	}

	// Disconnect from the peer if it does not specify all required services.
	if rp.services&reqSvcs != reqSvcs {
		go func() {
			if waitForAddrs != nil {
				<-waitForAddrs
			}
			log.Infof("Disconnecting from outbound peer %v due to improper services %v", rp.raddr, rp.services)
			rp.Disconnect()
		}()
		return nil, ErrMissingServices
	}

	return rp, nil
}

// Listen accepts inbound TCP connections from lis and begins peering with
// remote peers.  When the context is cancelled, no more connections are
// accepted from lis, but peering with existing connections continues.
func (lp *LocalPeer) Listen(ctx context.Context, lis net.Listener) error {
	e := make(chan error, 1)

	if _, ok := lis.(*net.TCPListener); !ok {
		return errors.New("lis must be a TCP listener")
	}

	go func() {
		// TODO: external addresses can be guessed from inbounding peer's
		// remote address of us.  For now, use the address of the listener
		//extaddr := lis.Addr()
		for {
			c, err := lis.Accept()
			if err != nil {
				e <- err
				return
			}
			go lp.serveInbound(lp.extaddr, c)
		}
	}()

	select {
	case <-ctx.Done():
		lis.Close()
		return ctx.Err()
	case err := <-e:
		return err
	}
}

// AddrManager returns the local peer's address manager.
func (lp *LocalPeer) AddrManager() *addrmgr.AddrManager { return lp.amgr }

// NA returns the remote peer's net address.
func (rp *RemotePeer) NA() *wire.NetAddress { return rp.na }

// InvsSent returns an LRU cache of inventory hashes sent to the remote peer.
func (rp *RemotePeer) InvsSent() *lru.Cache { return &rp.invsSent }

// InvsRecv returns an LRU cache of inventory hashes received by the remote
// peer.
func (rp *RemotePeer) InvsRecv() *lru.Cache { return &rp.invsRecv }

// DNSSeed uses DNS to seed the local peer with remote addresses matching the
// services.
func (lp *LocalPeer) DNSSeed(services wire.ServiceFlag) {
	connmgr.SeedFromDNS(lp.chainParams, services, net.LookupIP, func(addrs []*wire.NetAddress) {
		for _, a := range addrs {
			as := &net.TCPAddr{IP: a.IP, Port: int(a.Port)}
			log.Debugf("Discovered peer %v from seeder", as)
		}
		lp.amgr.AddAddresses(addrs, addrs[0])
	})
}

type msgReader struct {
	r      io.Reader
	net    wire.CurrencyNet
	msg    wire.Message
	rawMsg []byte
	err    error
}

func (mr *msgReader) next(pver uint32) bool {
	mr.msg, mr.rawMsg, mr.err = wire.ReadMessage(mr.r, pver, mr.net)
	return mr.err == nil
}

type syncWriter struct {
	w    io.Writer
	pver uint32
	net  wire.CurrencyNet
}

func (sw *syncWriter) write(ctx context.Context, out, outPrio <-chan wire.Message) error {
	e := make(chan error, 1)
	go func() {
		for {
			var msg wire.Message
			select {
			case msg = <-outPrio:
			default:
				select {
				case msg = <-outPrio:
				case msg = <-out:
				}
			}
			log.Debugf("Writing %s message", msg.Command())
			err := wire.WriteMessage(sw.w, msg, Pver, sw.net)
			if err != nil {
				e <- err
				return
			}
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-e:
		return err
	}
}

type msgWriter struct {
	w   io.Writer
	net wire.CurrencyNet
}

func (mw *msgWriter) write(ctx context.Context, msg wire.Message, pver uint32) error {
	e := make(chan error, 1)
	go func() {
		e <- wire.WriteMessage(mw.w, msg, pver, mw.net)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-e:
		return err
	}
}

func (lp *LocalPeer) serveInbound(extaddr net.Addr, c net.Conn) {
	// defer c.Close()

	// rp := RemotePeer{
	// 	mr:    msgReader{r: c, net: lp.chainParams.Net},
	// 	mw:    msgWriter{w: c, net: lp.chainParams.Net},
	// 	raddr: c.RemoteAddr(),
	// 	pver:  pver,
	// }

	// // The first message received must be the version message.
	// if !rp.mr.next(pver) {
	// 	log.Warnf("Inbound peer %v: %v", rp.raddr, rp.mr.err)
	// 	return
	// }
	// rversion, ok := mr.msg.(*wire.MsgVersion)
	// if !ok {
	// 	log.Warnf("Inbound peer %v: protocol error: first message was not the version message", rp.raddr)
	// 	// TODO: reject?
	// 	return
	// }
	// if lp.nonceMRU.contains(rversion.Nonce) {
	// 	log.Warnf("Inbound peer %v: preventing possible self connection", rp.raddr)
	// 	return
	// }
	// // TODO: Try to avoid duplicate and duplex connections
	// if rversion.ProtocolVersion < rp.pver {
	// 	// Negotiate protocol down to compatible version
	// 	rp.pver = rversion.ProtocolVersion
	// }

	// // Reply with our own version message
	// lversion, err := lp.newMsgVersion(rp.pver, extaddr, c)
	// if err != nil {
	// 	log.Errorf("Failed to create version message: %v", err)
	// 	return
	// }
	// if !rp.mw.next(lversion, rp.pver) {
	// 	log.Warnf("Inbound peer %v: failed to respond to version: %v", rp.raddr, rp.mw.err)
	// 	return
	// }

	// // Send the verack
	// if !rp.mw.next(wire.NewMsgVerAck(), rp.pver) {
	// 	log.Warnf("Inbound peer %v: faild to respond with verack: %v", rp.raddr, rp.mw.err)
	// 	return
	// }

	// // Wait until a verack is received
	// if !rp.mr.next(rp.pver) {
	// 	log.Warnf("Inbound peer %v: %v", rp.raddr, rp.mr.err)
	// 	return
	// }
	// if _, ok := rp.mr.msg.(*wire.MsgVerAck); !ok {
	// 	log.Warnf("Inbound peer %v: protocol error: did not receive verack", rp.raddr)
	// 	return
	// }

	// outQueue := make(chan wire.Message, 5000)

	// // TODO: add to local peer

	// defer func() {
	// 	// TODO: remove from local peer
	// }()

	// for mr.next() {
	// 	msg := mr.msg
	// 	if _, ok := msg.(*wire.MsgVersion); ok {
	// 		// TODO: reject duplicate version message
	// 		return
	// 	}
	// 	go func() {
	// 		switch mr.msg.(type) {

	// 		}
	// 	}()
	// }
	// if mr.err != nil {
	// 	if mr.err == io.EOF {
	// 		log.Infof("Inbound peer %v: disconnected", rp.raddr)
	// 		return
	// 	}

	// 	log.Warnf("Inbound peer %v: %v", rp.raddr, err)
	// }
}

// readMessageDeadline reads a message from a connection with a new deadline.
// The connection's read deadline is not reset before returning.
func readMessageDeadline(c net.Conn, deadline time.Duration, pver uint32, cnet wire.CurrencyNet) (wire.Message, error) {
	err := c.SetReadDeadline(time.Now().Add(deadline))
	if err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %v", err)
	}
	msg, _, err := wire.ReadMessage(c, pver, cnet)
	return msg, err
}

func handshake(ctx context.Context, lp *LocalPeer, id uint64, na *wire.NetAddress, c net.Conn) (*RemotePeer, error) {
	rp := &RemotePeer{
		id:       id,
		lp:       lp,
		ua:       "",
		services: 0,
		pver:     Pver,
		raddr:    c.RemoteAddr(),
		na:       na,
		c:        c,
		mr:       msgReader{r: c, net: lp.chainParams.Net},
		out:      nil,
		outPrio:  nil,
		invsSent: lru.NewCache(invLRUSize),
		invsRecv: lru.NewCache(invLRUSize),
		errc:     make(chan struct{}),
	}

	mw := msgWriter{c, lp.chainParams.Net}

	// The first message sent must be the version message.
	lversion, err := lp.newMsgVersion(rp.pver, lp.extaddr, c)
	if err != nil {
		return nil, fmt.Errorf("failed to create version message: %v", err)
	}
	err = mw.write(ctx, lversion, rp.pver)
	if err != nil {
		return nil, fmt.Errorf("failed to send version: %v", err)
	}

	// The first message received must also be a version message.
	msg, err := readMessageDeadline(c, 3*time.Second, Pver, lp.chainParams.Net)
	if err != nil {
		return nil, err
	}
	rversion, ok := msg.(*wire.MsgVersion)
	if !ok {
		return nil, errors.New("protocol error: first received message was not the version message")
	}
	if lp.nonceLRU.Contains(rversion.Nonce) {
		return nil, errors.New("self connection")
	}
	rp.services = rversion.Services

	// Negotiate protocol down to compatible version
	if uint32(rversion.ProtocolVersion) < rp.pver {
		rp.pver = uint32(rversion.ProtocolVersion)
	}

	// Send the verack
	err = mw.write(ctx, wire.NewMsgVerAck(), rp.pver)
	if err != nil {
		return nil, fmt.Errorf("failed to respond with verack: %v", err)
	}

	// Wait until a verack is received
	msg, err = readMessageDeadline(c, 3*time.Second, rp.pver, lp.chainParams.Net)
	if err != nil {
		return nil, err
	}
	_, ok = msg.(*wire.MsgVerAck)
	if !ok {
		return nil, errors.New("protocol error: did not receive verack")
	}

	rp.out = make(chan wire.Message)
	rp.outPrio = make(chan wire.Message)

	return rp, nil
}

func (lp *LocalPeer) connectOutbound(ctx context.Context, id uint64, addr string) (*RemotePeer, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Create a net address with assumed services.
	na := wire.NewNetAddressTimestamp(time.Now(),
		wire.SFNodeNetwork|wire.SFNodeCF, tcpAddr.IP, uint16(tcpAddr.Port))

	var c net.Conn
	var retryDuration = 5 * time.Second
	timer := time.NewTimer(retryDuration)
	for {
		// Mark the connection attempt.
		lp.amgr.Attempt(na)

		// Dial with a timeout of 10 seconds.
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		c, err = lp.dialer.DialContext(dialCtx, "tcp", addr)
		cancel()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		select {
		case <-ctx.Done():

			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
			if retryDuration < 200*time.Second {
				retryDuration += 5 * time.Second
				timer.Reset(retryDuration)
			}
		}
	}
	lp.amgr.Connected(na)
	lp.rpMu.Lock()
	lp.rpConns[id].attempts = 0
	lp.rpConns[id].state = connHandshaking
	lp.rpMu.Unlock()

	rp, err := handshake(ctx, lp, id, na, c)
	if err != nil {
		return nil, fmt.Errorf("handshake: %v", err)
	}

	// Add rp to local peer in peering state.
	lp.rpMu.Lock()
	lp.rpByID[rp.id] = rp
	lp.rpConns[id].state = connPeering
	lp.rpMu.Unlock()

	// The real services of the net address are now known.
	na.Services = rp.services

	// Mark this as a good address.
	lp.amgr.Good(na)

	return rp, nil
}

func (lp *LocalPeer) serveUntilError(ctx context.Context, rp *RemotePeer) {
	defer func() {
		// Remove from local peer
		log.Infof("Disconnected from outbound peer %v", rp.raddr)
		lp.rpMu.Lock()
		delete(lp.rpByID, rp.id)
		lp.rpConns[rp.id].state = connIdle
		lp.rpMu.Unlock()
	}()

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() (err error) {
		defer func() {
			if err != nil {
				log.Errorf("RemotePeer.readMessages: %v", err)
			}
		}()
		return rp.readMessages(gctx)
	})
	g.Go(func() (err error) {
		defer func() {
			if err != nil && err != context.Canceled {
				log.Errorf("syncWriter.write(%v): %v", rp.raddr, err)
			}
		}()
		sw := syncWriter{rp.c, rp.pver, lp.chainParams.Net}
		return sw.write(gctx, rp.out, rp.outPrio)
	})
	err := g.Wait()
	if err != nil {
		log.Warnf("Peering with outbound peer %v ended: %v", rp.raddr, err)
		rp.err = err
		close(rp.errc)
	}
}

// Disconnect closes the underlying TCP connection to a RemotePeer.
func (rp *RemotePeer) Disconnect() error {
	log.Debugf("Disconnecting %v", rp.raddr)
	debug.PrintStack()
	return rp.c.Close()
}

// Err blocks until the RemotePeer finishes peering, returning the final error.
func (rp *RemotePeer) Err() error {
	<-rp.errc
	return rp.err
}

// RemoteAddr returns the remote address of the peer's TCP connection.
func (rp *RemotePeer) RemoteAddr() net.Addr {
	return rp.c.RemoteAddr()
}

type inMsg struct {
	rp  *RemotePeer
	msg wire.Message
}

var inMsgPool = sync.Pool{
	New: func() interface{} { return new(inMsg) },
}

func newInMsg(rp *RemotePeer, msg wire.Message) *inMsg {
	m := inMsgPool.Get().(*inMsg)
	m.rp = rp
	m.msg = msg
	return m
}

func recycleInMsg(m *inMsg) {
	*m = inMsg{}
	inMsgPool.Put(m)
}

func (rp *RemotePeer) readMessages(ctx context.Context) error {
	for rp.mr.next(rp.pver) {
		msg := rp.mr.msg
		log.Tracef("Outbound peer %v: received message %#v", rp.raddr, msg)
		if _, ok := msg.(*wire.MsgVersion); ok {
			// TODO: reject duplicate version message
			return errors.New("received unexpected version message")
		}
		go func() {
			switch m := msg.(type) {
			case *wire.MsgAddr:
				rp.lp.amgr.AddAddresses(m.AddrList, rp.na)
			case *wire.MsgBlock:
				rp.receivedBlock(ctx, m)
			case *wire.MsgCFilter:
				rp.receivedCFilter(ctx, m)
			case *wire.MsgGetData:
				rp.receivedGetData(ctx, m)
			case *wire.MsgHeaders:
				rp.receivedHeaders(ctx, m)
			case *wire.MsgInv:
				if rp.lp.messageIsMasked(MaskInv) {
					rp.lp.receivedInv <- newInMsg(rp, msg)
				}
			case *wire.MsgPing:
				pong(ctx, m, rp)
			}
		}()
	}
	return rp.mr.err
}

func pong(ctx context.Context, ping *wire.MsgPing, rp *RemotePeer) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	select {
	case <-ctx.Done():
	case rp.outPrio <- wire.NewMsgPong(ping.Nonce):
	}
}

// MessageMask is a bitmask of message types that can be received and handled by
// consumers of this package by calling various Receive* methods on a LocalPeer.
// Received messages not in the mask are ignored, while messages in the mask
// must be read by the .  Handled messages can be added and removed by using the
// AddHandledMessages and RemoveHandledMessages methods of a LocalPeer.
type MessageMask uint64

// Message mask constants
const (
	MaskGetData MessageMask = 1 << iota
	MaskInv
)

// AddHandledMessages adds all messages defined by the bitmask.  This operation
// is concurrent-safe.
func (lp *LocalPeer) AddHandledMessages(mask MessageMask) {
	for {
		p := atomic.LoadUint64(&lp.atomicMask)
		n := p | uint64(mask)
		if atomic.CompareAndSwapUint64(&lp.atomicMask, p, n) {
			return
		}
	}
}

// RemoveHandledMessages removes all messages defined by the bitmask.  This
// operation is concurrent safe.
func (lp *LocalPeer) RemoveHandledMessages(mask MessageMask) {
	for {
		p := atomic.LoadUint64(&lp.atomicMask)
		n := p &^ uint64(mask)
		if atomic.CompareAndSwapUint64(&lp.atomicMask, p, n) {
			return
		}
	}
}

func (lp *LocalPeer) messageIsMasked(m MessageMask) bool {
	return atomic.LoadUint64(&lp.atomicMask)&uint64(m) != 0
}

// ReceiveGetData waits for a getdata message from a remote peer, returning the
// peer that sent the message, and the message itself.
func (lp *LocalPeer) ReceiveGetData(ctx context.Context) (*RemotePeer, *wire.MsgGetData, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case r := <-lp.receivedGetData:
		rp, msg := r.rp, r.msg.(*wire.MsgGetData)
		recycleInMsg(r)
		return rp, msg, nil
	}
}

// ReceiveInv waits for an inventory message from a remote peer, returning the
// peer that sent the message, and the message itself.
func (lp *LocalPeer) ReceiveInv(ctx context.Context) (*RemotePeer, *wire.MsgInv, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case r := <-lp.receivedInv:
		rp, msg := r.rp, r.msg.(*wire.MsgInv)
		recycleInMsg(r)
		return rp, msg, nil
	}
}

// ReceiveHeadersAnnouncement returns any unrequested headers that were
// announced without an inventory message due to a previous sendheaders request.
func (lp *LocalPeer) ReceiveHeadersAnnouncement(ctx context.Context) (*RemotePeer, []*wire.BlockHeader, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case r := <-lp.announcedHeaders:
		rp, msg := r.rp, r.msg.(*wire.MsgHeaders)
		recycleInMsg(r)
		return rp, msg.Headers, nil
	}
}

// addRequestBlock records the channel that a requested block is sent to when
// the block message is received.  If a block has already been requested, this
// returns false and the getdata request should not be queued.
func (rp *RemotePeer) addRequestedBlock(hash *chainhash.Hash, c chan<- *wire.MsgBlock) (newRequest bool) {
	_, loaded := rp.requestedBlocks.LoadOrStore(*hash, c)
	return !loaded
}

func (rp *RemotePeer) deleteRequestedBlock(hash *chainhash.Hash) {
	rp.requestedBlocks.Delete(*hash)
}

func (rp *RemotePeer) receivedBlock(ctx context.Context, msg *wire.MsgBlock) {
	blockHash := msg.Header.BlockHash()
	var k interface{} = blockHash
	v, ok := rp.requestedBlocks.Load(k)
	if !ok {
		log.Warnf("Remote peer %v: received unrequested block %v", rp.raddr, &blockHash)
		//r.misbehaving()
	}
	rp.requestedBlocks.Delete(k)
	c := v.(chan<- *wire.MsgBlock)
	select {
	case <-ctx.Done():
	case c <- msg:
	}
}

func (rp *RemotePeer) addRequestedCFilter(hash *chainhash.Hash, c chan<- *wire.MsgCFilter) (newRequest bool) {
	_, loaded := rp.requestedCFilters.LoadOrStore(*hash, c)
	return !loaded
}

func (rp *RemotePeer) deleteRequestedCFilter(hash *chainhash.Hash) {
	rp.requestedCFilters.Delete(*hash)
}

func (rp *RemotePeer) receivedCFilter(ctx context.Context, msg *wire.MsgCFilter) {
	var k interface{} = msg.BlockHash
	v, ok := rp.requestedCFilters.Load(k)
	if !ok {
		log.Warnf("Remote peer %v: received unrequested cfilter", rp.raddr)
		//r.misbehaving()
	}
	rp.requestedCFilters.Delete(k)
	c := v.(chan<- *wire.MsgCFilter)
	select {
	case <-ctx.Done():
	case c <- msg:
	}
}

func (rp *RemotePeer) addRequestedHeaders(c chan<- *wire.MsgHeaders) (sendheaders, newRequest bool) {
	rp.requestedHeadersMu.Lock()
	if rp.sendheaders {
		return true, false
	}
	if rp.requestedHeaders != nil {
		rp.requestedHeadersMu.Unlock()
		return false, false
	}
	rp.requestedHeaders = c
	rp.requestedHeadersMu.Unlock()
	return false, true
}

func (rp *RemotePeer) deleteRequestedHeaders() {
	rp.requestedHeadersMu.Lock()
	rp.requestedHeaders = nil
	rp.requestedHeadersMu.Unlock()
}

func (rp *RemotePeer) receivedHeaders(ctx context.Context, msg *wire.MsgHeaders) {
	rp.requestedHeadersMu.Lock()
	if rp.sendheaders {
		rp.requestedHeadersMu.Unlock()
		select {
		case <-ctx.Done():
		case rp.lp.announcedHeaders <- newInMsg(rp, msg):
		}
		return
	}
	if rp.requestedHeaders == nil {
		log.Warnf("Remote peer %v: received unrequested headers", rp.raddr)
		//rp.misbehaving()
	}
	c := rp.requestedHeaders
	rp.requestedHeaders = nil
	rp.requestedHeadersMu.Unlock()
	select {
	case <-ctx.Done():
	case c <- msg:
	}
}

func (rp *RemotePeer) receivedGetData(ctx context.Context, msg *wire.MsgGetData) {
	if rp.banScore.Increase(0, uint32(len(msg.InvList))*banThreshold/wire.MaxInvPerMsg) > banThreshold {
		log.Warnf("%v: ban score reached threshold", rp.RemoteAddr())
		// rp.misbehaving()
		return
	}

	if rp.lp.messageIsMasked(MaskInv) {
		rp.lp.receivedGetData <- newInMsg(rp, msg)
	}
}

// GetAddrs requests a list of known active peers from a RemotePeer.  As many
// addr responses may be received for a single getaddr request, received address
// messages are handled asynchronously by the local peer and at least the stall
// timeout should be waited before disconnecting a remote peer while waiting for
// addr messages.
func (rp *RemotePeer) GetAddrs(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, stallTimeout)
	defer cancel()
	m := wire.NewMsgGetAddr()
	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			log.Warnf("Deadline exceeded on getaddr response, disconnecting stalled peer %v", rp.raddr)
			// rp.stalled()
		}
		return ctx.Err()
	case rp.out <- m:
		return nil
	}
}

// GetBlock requests a block from a RemotePeer.  The same block can not be
// requested multiple times concurrently from the same peer.
func (rp *RemotePeer) GetBlock(ctx context.Context, blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	ctx, cancel := context.WithTimeout(ctx, stallTimeout)
	defer cancel()
	m := wire.NewMsgGetDataSizeHint(1)
	err := m.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, blockHash))
	if err != nil {
		return nil, err
	}
	c := make(chan *wire.MsgBlock, 1)
	if !rp.addRequestedBlock(blockHash, c) {
		return nil, errors.New("block is already being requested from this peer")
	}
	out := rp.out
	for {
		select {
		case <-ctx.Done():
			rp.deleteRequestedBlock(blockHash)
			if ctx.Err() == context.DeadlineExceeded {
				log.Warnf("Deadline exceeded on getblock response, disconnecting stalled peer %v", rp.raddr)
				// rp.stalled()
			}
			return nil, ctx.Err()
		case out <- m:
			out = nil
		case m := <-c:
			return m, nil
		}
	}
}

// GetBlocks requests multiple blocks at a time from a RemotePeer using a single
// getdata message.  It returns when all of the blocks have been received.  The
// same block may not be requested multiple times concurrently from the same
// peer.
func (rp *RemotePeer) GetBlocks(ctx context.Context, blockHashes []*chainhash.Hash) ([]*wire.MsgBlock, error) {
	ctx, cancel := context.WithTimeout(ctx, stallTimeout)
	defer cancel()
	m := wire.NewMsgGetDataSizeHint(uint(len(blockHashes)))
	cs := make([]chan *wire.MsgBlock, len(blockHashes))
	for i, h := range blockHashes {
		err := m.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, h))
		if err != nil {
			return nil, err
		}
		cs[i] = make(chan *wire.MsgBlock, 1)
		if !rp.addRequestedBlock(h, cs[i]) {
			for _, h := range blockHashes[:i] {
				rp.deleteRequestedBlock(h)
			}
			return nil, errors.New("block is a already being requested from this peer")
		}
	}
	select {
	case <-ctx.Done():
		for _, h := range blockHashes {
			rp.deleteRequestedBlock(h)
		}
		return nil, ctx.Err()
	case rp.out <- m:
	}
	blocks := make([]*wire.MsgBlock, len(blockHashes))
	for i := 0; i < len(blockHashes); i++ {
		select {
		case <-ctx.Done():
			for _, h := range blockHashes[i:] {
				rp.deleteRequestedBlock(h)
			}
			if ctx.Err() == context.DeadlineExceeded {
				log.Warnf("Deadline exceeded on getblock response, disconnecting stalled peer %v", rp.raddr)
				// rp.stalled()
			}
			return nil, ctx.Err()
		case m := <-cs[i]:
			blocks[i] = m
		}
	}
	return blocks, nil
}

// GetCFilter requests a regular compact filter from a RemotePeer.  The same
// block can not be requested concurrently from the same peer.
func (rp *RemotePeer) GetCFilter(ctx context.Context, blockHash *chainhash.Hash) (*gcs.Filter, error) {
	ctx, cancel := context.WithTimeout(ctx, stallTimeout)
	defer cancel()
	m := wire.NewMsgGetCFilter(blockHash, wire.GCSFilterRegular)
	c := make(chan *wire.MsgCFilter)
	if !rp.addRequestedCFilter(blockHash, c) {
		return nil, errors.New("cfilter is already being requested from this peer for this block")
	}
	out := rp.out
	for {
		select {
		case <-ctx.Done():
			rp.deleteRequestedCFilter(blockHash)
			if ctx.Err() == context.DeadlineExceeded {
				log.Warnf("Deadline exceeded on getcfilter response, disconnecting stalled peer %v", rp.raddr)
				// rp.stalled()
			}
			return nil, ctx.Err()
		case out <- m:
			out = nil
		case m := <-c:
			if len(m.Data) == 0 {
				return gcs.FromBytes(0, blockcf.P, nil)
			}
			return gcs.FromNBytes(blockcf.P, m.Data)
		}
	}
}

// SendHeaders sends the remote peer a sendheaders message.  This informs the
// peer to announce new blocks by immediately sending them in a headers message
// rather than sending an inv message containing the block hash.
//
// Once this is called, it is no longer permitted to use the synchronous
// GetHeaders method, as there is no guarantee that the next received headers
// message corresponds with any getheaders request.
func (rp *RemotePeer) SendHeaders(ctx context.Context) error {
	// If negotiated protocol version allows it, and the option is set, request
	// blocks to be announced by pushing headers messages.
	if rp.pver < wire.SendHeadersVersion {
		return fmt.Errorf("protocol version %v is too low to receive "+
			"block header announcements from peer %v", rp.pver, rp.raddr)
	}

	rp.requestedHeadersMu.Lock()
	rp.sendheaders = true
	rp.requestedHeadersMu.Unlock()
	select {
	case <-ctx.Done():
		rp.requestedHeadersMu.Lock()
		rp.sendheaders = false
		rp.requestedHeadersMu.Unlock()
		return ctx.Err()
	case rp.out <- wire.NewMsgSendHeaders():
		return nil
	}
}

// GetHeaders requests block headers from the RemotePeer.  Block headers can not
// be requested concurrently from the same peer.  Sending a getheaders message
// and synchronously waiting for the result is not possible if a sendheaders
// message has been sent to the remote peer.
func (rp *RemotePeer) GetHeaders(ctx context.Context, blockLocators []*chainhash.Hash, hashStop *chainhash.Hash) (*wire.MsgHeaders, error) {
	ctx, cancel := context.WithTimeout(ctx, stallTimeout*3) // allow additional time to fetch headers
	defer cancel()
	m := &wire.MsgGetHeaders{
		ProtocolVersion:    rp.pver,
		BlockLocatorHashes: blockLocators,
		HashStop:           *hashStop,
	}
	c := make(chan *wire.MsgHeaders)
	sendheaders, newRequest := rp.addRequestedHeaders(c)
	if sendheaders {
		return nil, errors.New("synchronous getheaders after sendheaders is unsupported")
	}
	if !newRequest {
		return nil, errors.New("headers are already being requested from this peer")
	}
	out := rp.out
	for {
		select {
		case <-ctx.Done():
			rp.deleteRequestedHeaders()
			// not guaranteed to get a headers message for a getheaders request, so
			// don't disconnect the peer.
			return nil, ctx.Err()
		case out <- m:
			out = nil
		case m := <-c:
			return m, nil
		}
	}
}

// SendMessage sends an message to the remote peer.  Use this method carefully,
// as calling this with an unexpected message that changes the protocol state
// may cause problems with the convenience methods implemented by this package.
func (rp *RemotePeer) SendMessage(ctx context.Context, msg wire.Message) error {
	ctx, cancel := context.WithTimeout(ctx, stallTimeout)
	defer cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case rp.out <- msg:
		return nil
	}
}
