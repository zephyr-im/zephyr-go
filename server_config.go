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
	"net"

	"github.com/zephyr-im/hesiod-go"
)

// A ServerConfig describes how to connect to a given zephyrd
// instance.
type ServerConfig interface {
	// ResolveServer returns a list of zephyrd addresses to
	// round-robin connect to. This may be repeatedly to refresh
	// this list. ResolveServer cannot return a list of length 0.
	ResolveServer() ([]*net.UDPAddr, error)
}

type staticConfig []*net.UDPAddr

// NewStaticServer returns a ServerConfig which returns a static list
// of zephyr server addresses.
func NewStaticServer(addrs []*net.UDPAddr) ServerConfig {
	if len(addrs) == 0 {
		panic("no addresses supplied")
	}
	return staticConfig(addrs)
}

func (s staticConfig) ResolveServer() ([]*net.UDPAddr, error) {
	return []*net.UDPAddr(s), nil
}

type hesiodConfig struct {
	hs   *hesiod.Hesiod
	port int
}

// NewServerFromHesiod creates the server configuration for a zephyr
// installation at a Hesiod realm.
func NewServerFromHesiod(hs *hesiod.Hesiod) (ServerConfig, error) {
	// Get the port. This is shared among all instances.
	svc, err := hs.GetServiceByName("zephyr-clt", "udp")
	if err != nil {
		return nil, err
	}
	return &hesiodConfig{hs, svc.Port}, nil
}

func (hc *hesiodConfig) ResolveServer() ([]*net.UDPAddr, error) {
	zephyrds, err := hc.hs.Resolve("zephyr", "sloc")
	if err != nil {
		return nil, err
	}
	if len(zephyrds) == 0 {
		return nil, errors.New("no zephyrds found")
	}
	// Go ahead resolve them all now. Not much use in being lazy
	// here.
	addrs := make([]*net.UDPAddr, len(zephyrds))
	for i, zephyrd := range zephyrds {
		addr, err := net.ResolveIPAddr("ip", zephyrd)
		if err != nil {
			return nil, err
		}
		addrs[i] = &net.UDPAddr{IP: addr.IP, Port: hc.port, Zone: addr.Zone}
	}
	return addrs, nil
}
