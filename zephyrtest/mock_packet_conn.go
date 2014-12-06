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

package zephyrtest

import (
	"io"
	"net"
	"time"
)

// A PacketRead is the result of a ReadFrom call on a MockPacketConn.
type PacketRead struct {
	Packet []byte
	Addr   net.Addr
	Err    error
}

// A PacketWrite is WriteTo call on a MockPacketConn. The call blocks
// until an error or nil is written into Result.
type PacketWrite struct {
	Packet []byte
	Addr   net.Addr
	Result chan error
}

// A MockPacketConn is a mocked PacketConn implementation for testing
// purposes.
type MockPacketConn struct {
	localAddr net.Addr
	reads     <-chan PacketRead
	writes    chan PacketWrite
	closed    chan int
}

// NewMockPacketConn creates a new mock packet connection for a given
// local address and read channel.
func NewMockPacketConn(localAddr net.Addr, reads <-chan PacketRead) *MockPacketConn {
	c := new(MockPacketConn)
	c.localAddr = localAddr
	c.reads = reads
	c.writes = make(chan PacketWrite)
	c.closed = make(chan int, 1)
	return c
}

// Writes returns a channel of PacketWrites for each write.
func (c *MockPacketConn) Writes() <-chan PacketWrite {
	return c.writes
}

// ReadFrom consumes the next read in the mock connection's reads
// channel.
func (c *MockPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case read, ok := <-c.reads:
		if !ok {
			return 0, nil, io.EOF
		}
		if read.Err != nil {
			return 0, nil, read.Err
		}
		n := copy(b, read.Packet)
		return n, read.Addr, nil
	case <-c.closed:
		c.closed <- 0
		return 0, nil, io.EOF
	}
}

// WriteTo sends a PacketWrite to the mock connection's writes
// channel.
func (c *MockPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	bcopy := make([]byte, len(b))
	copy(bcopy, b)
	ret := make(chan error)
	c.writes <- PacketWrite{bcopy, addr, ret}
	err := <-ret
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close closes this mock connection, interrupting any ReadFrom in
// progress.
func (c *MockPacketConn) Close() error {
	c.closed <- 0
	close(c.writes)
	return nil
}

// LocalAddr returns the mocked local address of this connection.
func (c *MockPacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

// SetDeadline is not implemented.
func (c *MockPacketConn) SetDeadline(t time.Time) error {
	panic("Not implemented")
}

// SetReadDeadline is not implemented.
func (c *MockPacketConn) SetReadDeadline(t time.Time) error {
	panic("Not implemented")
}

// SetWriteDeadline is not implemented.
func (c *MockPacketConn) SetWriteDeadline(t time.Time) error {
	panic("Not implemented")
}

func indexOfAddr(haystack []net.Addr, needle net.Addr) int {
	for i, straw := range haystack {
		// Bah.
		if straw.String() == needle.String() {
			return i
		}
	}
	return -1
}

// NewMockPacketNetwork returns a list of mock PacketConn
// implementations, one for each input address. A WriteTo call in one
// PacketConn will be routed to the appropriate destination PacketConn
// and read back.
func NewMockPacketNetwork(addrs []net.Addr) []net.PacketConn {
	sinks := make([]chan<- PacketRead, len(addrs))
	conns := make([]*MockPacketConn, len(addrs))
	ret := make([]net.PacketConn, len(addrs))

	// Create connections and link them all together.
	for i := range addrs {
		readChan := make(chan PacketRead)
		conn := NewMockPacketConn(addrs[i], readChan)
		sinks[i] = readChan
		conns[i] = conn
		ret[i] = conn

		go func(i int) {
			for write := range conns[i].Writes() {
				// Writes in a mock network succeed.
				write.Result <- nil

				// Direct the write to the appropriate node.
				dst := indexOfAddr(addrs, write.Addr)
				if dst < 0 {
					// Don't allow this.
					panic(write)
				}
				pkt := make([]byte, len(write.Packet))
				copy(pkt, write.Packet)
				sinks[dst] <- PacketRead{write.Packet, addrs[i], nil}
			}
		}(i)
	}

	return ret
}
