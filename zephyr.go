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

// Package zephyr provides a Go zephyr protocol implementation.
//
// The Session API provides a high-level interface to the protocol and
// is one most users will likely use. The Dial functions create
// Sessions with default non-mock parameters and system-default
// parameters.
//
// More specialized clients can use the lower-level Connection API
// which allows for more specialized handling of ACKs and message
// reassembly while implementing server discovery and retransmit
// schedule. There are also even lower-level notice-parsing functions
// for even lower-level clients.
package zephyr

import (
	"log"
	"net"

	"github.com/zephyr-im/hesiod-go"
	"github.com/zephyr-im/krb5-go"
)

// DialSystemDefault opens a new Session using credentials from the
// default ccache and using the system-wide Hesiod config to find the
// zephyrds.
func DialSystemDefault() (*Session, error) {
	ctx, err := krb5.NewContext()
	if err != nil {
		return nil, err
	}
	defer ctx.Free()
	ccache, err := ctx.DefaultCCache()
	if err != nil {
		return nil, err
	}
	defer ccache.Close()
	client, err := ccache.Principal()
	if err != nil {
		return nil, err
	}
	service, err := ctx.ParseName("zephyr/zephyr")
	if err != nil {
		return nil, err
	}
	cred, err := ctx.GetCredential(ccache, client, service)
	if err != nil {
		return nil, err
	}
	return Dial(hesiod.NewHesiod(), cred, nil)
}

// Dial creates a new Session using the given Hesiod object and
// credential.
func Dial(
	hesiod *hesiod.Hesiod,
	cred *krb5.Credential,
	logger *log.Logger,
) (*Session, error) {
	// Create a server config from Hesiod.
	server, err := NewServerFromHesiod(hesiod)
	if err != nil {
		return nil, err
	}

	// Listen on a socket.
	udp, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}

	return NewSession(udp, server, cred, logger)
}
