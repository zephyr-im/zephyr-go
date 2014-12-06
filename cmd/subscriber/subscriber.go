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

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/zephyr-im/krb5-go"
	"github.com/zephyr-im/zephyr-go"
)

func main() {
	flag.Parse()
	if flag.NArg() != 2 {
		log.Fatal("Need 2 arguments")
	}
	subs := []zephyr.Subscription{
		{"", flag.Arg(0), flag.Arg(1)},
	}

	// Open a session.
	session, err := zephyr.DialSystemDefault()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()
	go func() {
		for r := range session.Messages() {
			log.Printf("Received message %v %v", r.AuthStatus, r.Message)
		}
	}()

	log.Printf("Subscribing to %v", subs)
	ctx, err := krb5.NewContext()
	if err != nil {
		log.Fatal(err)
	}
	defer ctx.Free()
	ack, err := session.SendSubscribeNoDefaults(ctx, subs)
	log.Printf(" -> %v %v", ack, err)
	defer func() {
		log.Printf("Canceling subscriptions")
		ack, err := session.SendCancelSubscriptions(ctx)
		log.Printf(" -> %v %v", ack, err)
	}()

	// Keep listening until a SIGINT or SIGTERM.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
