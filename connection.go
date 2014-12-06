// Copyright 2014 The zephyr-go authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package zephyr

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/zephyr-im/krb5-go"
)

func localIPForUDPAddr(addr *net.UDPAddr) (net.IP, error) {
	bogus, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer bogus.Close()
	return bogus.LocalAddr().(*net.UDPAddr).IP, nil
}

func udpAddrsEqual(a, b *net.UDPAddr) bool {
	return a.IP.Equal(b.IP) && a.Port == b.Port && a.Zone == b.Zone
}

// How frequently we query for new servers.
const serverRefreshInterval = 10 * time.Minute

// A Connection represents a low-level connection to the Zephyr
// servers. It handles server discovery and sending and receiving
// Notices. It does not provide high-level constructs like subscribing
// or message sharding. It also does not automatically send
// CLIENTACKs.
type Connection struct {
	// Properties of the connection.
	conn    net.PacketConn
	server  ServerConfig
	cred    *krb5.Credential
	clock   Clock
	localIP net.IP

	// Incoming notices from the connection.
	allNotices <-chan NoticeReaderResult

	// Where non-ACK notices get dumped.
	notices chan NoticeReaderResult

	// Table of pending ACKs.
	ackTable     map[UID]chan NoticeReaderResult
	ackTableLock sync.Mutex

	// Current server send schedule.
	sched     []*net.UDPAddr
	schedIdx  int
	schedLock sync.Mutex

	stopRefreshing chan int
}

// NewConnection creates a new Connection wrapping a given
// net.PacketConn. The ServerConfig argument instructs the connection
// on how to locate the remote servers. The Credential is used to
// authenticate incoming and outgoing packets. The connection takes
// ownership of the PacketConn and will close it when Close is
// called.
func NewConnection(
	conn net.PacketConn,
	server ServerConfig,
	cred *krb5.Credential,
	logger *log.Logger,
) (*Connection, error) {
	return NewConnectionFull(conn, server, cred, logger, SystemClock)
}

// NewConnectionFull does the same as NewConnection but takes an
// additional Clock argument for testing.
func NewConnectionFull(
	conn net.PacketConn,
	server ServerConfig,
	cred *krb5.Credential,
	logger *log.Logger,
	clock Clock,
) (*Connection, error) {
	c := new(Connection)
	c.conn = conn
	c.server = server
	c.cred = cred
	c.clock = clock
	var key *krb5.KeyBlock
	if c.cred != nil {
		key = c.cred.KeyBlock
	}
	c.allNotices = ReadNoticesFromServer(conn, key, logger)
	c.notices = make(chan NoticeReaderResult)
	c.ackTable = make(map[UID]chan NoticeReaderResult)

	c.stopRefreshing = make(chan int, 1)

	if _, err := c.RefreshServer(); err != nil {
		return nil, err
	}
	localIP, err := localIPForUDPAddr(c.sched[0])
	if err != nil {
		return nil, err
	}
	c.localIP = localIP

	go c.readLoop()
	// This is kinda screwy. Purely for testing purposes, ensure
	// the first query on the clock happens by the time
	// NewConnectionFull returns. MockClock is a little messy.
	go c.refreshLoop(c.clock.After(serverRefreshInterval))
	return c, nil
}

// Notices returns the incoming notices from the connection.
func (c *Connection) Notices() <-chan NoticeReaderResult {
	return c.notices
}

// LocalAddr returns the local UDP address for the client when
// communicating with the Zephyr servers.
func (c *Connection) LocalAddr() *net.UDPAddr {
	addr := c.conn.LocalAddr().(*net.UDPAddr)
	addr.IP = c.localIP
	return addr
}

// Credential returns the credential for this connection.
func (c *Connection) Credential() *krb5.Credential {
	return c.cred
}

// Close closes the underlying connection.
func (c *Connection) Close() error {
	c.stopRefreshing <- 0
	return c.conn.Close()
}

func (c *Connection) readLoop() {
	for r := range c.allNotices {
		if r.Notice.Kind.IsServerACK() {
			c.processServAck(r)
		} else {
			c.notices <- r
		}
	}
	close(c.notices)
}

func (c *Connection) refreshLoop(after <-chan time.Time) {
	for {
		select {
		case <-after:
			c.RefreshServer()
			after = c.clock.After(serverRefreshInterval)
		case <-c.stopRefreshing:
			return
		}
	}
}

func (c *Connection) findPendingSend(uid UID) chan NoticeReaderResult {
	c.ackTableLock.Lock()
	defer c.ackTableLock.Unlock()
	if ps, ok := c.ackTable[uid]; ok {
		delete(c.ackTable, uid)
		return ps
	}
	return nil
}

func (c *Connection) addPendingSend(uid UID) <-chan NoticeReaderResult {
	// Buffer one entry; if the ACK and timeout race, the
	// sending thread should not lock up.
	ackChan := make(chan NoticeReaderResult, 1)
	c.ackTableLock.Lock()
	defer c.ackTableLock.Unlock()
	c.ackTable[uid] = ackChan
	return ackChan
}

func (c *Connection) clearPendingSend(uid UID) {
	c.ackTableLock.Lock()
	defer c.ackTableLock.Unlock()
	delete(c.ackTable, uid)
}

func (c *Connection) processServAck(r NoticeReaderResult) {
	ps := c.findPendingSend(r.Notice.UID)
	if ps != nil {
		ps <- r
	}
}

func (c *Connection) schedule() ([]*net.UDPAddr, int) {
	c.schedLock.Lock()
	defer c.schedLock.Unlock()
	return c.sched, c.schedIdx
}

func (c *Connection) setSchedule(sched []*net.UDPAddr, schedIdx int) {
	c.schedLock.Lock()
	defer c.schedLock.Unlock()
	c.sched = sched
	c.schedIdx = schedIdx
}

func (c *Connection) goodServer(good *net.UDPAddr) {
	c.schedLock.Lock()
	defer c.schedLock.Unlock()

	// Find the good server in the schedule and use it
	// preferentially next time.
	for i, addr := range c.sched {
		if udpAddrsEqual(addr, good) {
			c.schedIdx = i
			return
		}
	}
}

// RefreshServer forces a manual refresh of the server schedule from
// the ServerConfig. This will be called periodically and when
// outgoing messages time out, so there should be little need to call
// this manually.
func (c *Connection) RefreshServer() ([]*net.UDPAddr, error) {
	sched, err := c.server.ResolveServer()
	if err != nil {
		return nil, err
	}
	if len(sched) == 0 {
		panic(sched)
	}
	c.setSchedule(sched, 0)
	return sched, nil
}

// SendNotice sends an authenticated notice to the servers. If the
// notice expects an acknowledgement, it returns the SERVACK or
// SERVNAK notice from the server on success.
func (c *Connection) SendNotice(ctx *krb5.Context, n *Notice) (*Notice, error) {
	pkt, err := n.EncodePacketForServer(ctx, c.cred)
	if err != nil {
		return nil, err
	}
	return c.SendPacket(pkt, n.Kind, n.UID)
}

// SendNoticeUnauth sends an unauthenticated notice to the servers. If
// the notice expects an acknowledgement, it returns the SERVACK or
// SERVNAK notice from the server on success.
func (c *Connection) SendNoticeUnauth(n *Notice) (*Notice, error) {
	pkt := n.EncodePacketUnauth()
	return c.SendPacket(pkt, n.Kind, n.UID)
}

// SendNoticeUnackedTo sends an unauthenticated and unacked notice to
// a given destination. This is used to send a CLIENTACK to a received
// notice.
func (c *Connection) SendNoticeUnackedTo(n *Notice, addr net.Addr) error {
	pkt := n.EncodePacketUnauth()
	return c.SendPacketUnackedTo(pkt, addr)
}

// ErrPacketTooLong is returned when a notice or packet exceeds the
// maximum Zephyr packet size.
var ErrPacketTooLong = errors.New("packet too long")

// ErrSendTimeout is returned if a send times out without
// acknowledgement from the server.
var ErrSendTimeout = errors.New("send timeout")

// SendPacketUnackedTo sends a raw packet to a given destination.
func (c *Connection) SendPacketUnackedTo(pkt []byte, addr net.Addr) error {
	if len(pkt) > MaxPacketLength {
		return ErrPacketTooLong
	}
	_, err := c.conn.WriteTo(pkt, addr)
	return err
}

// TODO(davidben): We probably want to be more cleverer later. For
// now, follow a similar strategy to the real zhm, but use a much more
// aggressive rexmit schedule.
//
// Empirically, it seems to take 15-20ms for the zephyrds to ACK a
// notice.
var retrySchedule = []time.Duration{
	100 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
}

// If we've timed out 4 times, get a new server schedule.
const timeoutsBeforeRefresh = 4

// SendPacket sends a raw packet to the Zephyr servers. Based on kind
// and uid, it may wait for an acknowledgement. In that case, the
// SERVACK or SERVNAK notice will be returned. SendPacket rotates
// between the server instances and refreshes server list as necessary.
func (c *Connection) SendPacket(pkt []byte, kind Kind, uid UID) (*Notice, error) {
	// TODO(davidben): Should we limit the number of packets
	// in-flight as an ad-hoc congestion control?
	if len(pkt) > MaxPacketLength {
		return nil, ErrPacketTooLong
	}
	retryIdx := -1
	timeout := c.clock.After(0)

	// Listen for ACKs.
	var ackChan <-chan NoticeReaderResult
	var shouldClear bool
	if kind.ExpectsServerACK() {
		ackChan = c.addPendingSend(uid)
		shouldClear = true
		defer func() {
			if shouldClear {
				c.clearPendingSend(uid)
			}
		}()
	}

	// Get the remote server schedule.
	sched, schedIdx := c.schedule()
	if len(sched) == 0 {
		panic(sched)
	}

	for {
		select {
		case ack := <-ackChan:
			shouldClear = false // Already taken care of.
			// Record the good server so next time we
			// start at that one.
			c.goodServer(ack.Addr.(*net.UDPAddr))
			return ack.Notice, nil
		case <-timeout:
			retryIdx++
			if retryIdx >= len(retrySchedule) {
				return nil, ErrSendTimeout
			}

			// Partway through the re-xmit schedule, if we
			// still haven't heard back from any server,
			// get a fresh set of remote addresses.
			if retryIdx == timeoutsBeforeRefresh {
				var err error
				sched, err = c.RefreshServer()
				if err != nil {
					return nil, err
				}
				schedIdx = 0
			}

			addr := sched[schedIdx]
			if err := c.SendPacketUnackedTo(pkt, addr); err != nil {
				// TODO(davidben): Keep going on
				// temporary errors?
				return nil, err
			}
			if !kind.ExpectsServerACK() {
				return nil, nil
			}
			// Schedule the next timeout and move on to
			// the next server.
			timeout = c.clock.After(retrySchedule[retryIdx])
			schedIdx = (schedIdx + 1) % len(sched)
		}
	}
}
