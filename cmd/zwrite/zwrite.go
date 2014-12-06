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
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/zephyr-im/krb5-go"
	"github.com/zephyr-im/zephyr-go"
)

var class = "message"
var instance = "personal"
var opcode = ""
var signature = ""
var message = ""
var sender = ""
var haveSender = false
var auth = true
var expandTabs = true
var eofOnly = false
var realm = ""
var haveRealm = false
var recipients = []string{}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: zwrite [-a] [-d] [-t] [-l] [-u]")
	fmt.Fprintln(os.Stderr, "\t[-c class] [-i instance] [-O opcode] [-s signature] [-S sender]")
	fmt.Fprintln(os.Stderr, "\t[user...] [-r realm] [-m message]")
}

func parseFlagArg(flag, value string) {
	switch flag {
	case "-s":
		signature = value
	case "-c":
		class = value
	case "-i":
		instance = value
	case "-r":
		realm = value
		haveRealm = true
	case "-S":
		sender = value
		haveSender = true
	case "-O":
		opcode = value
	default:
		panic(flag)
	}
}

func readMessage(eofOnly bool) (string, error) {
	if eofOnly {
		fmt.Fprintln(os.Stderr, "Type your message now.  "+
			"End with the end-of-file character.")
		message, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		return string(message), nil
	}

	fmt.Fprintln(os.Stderr, "Type your message now.  "+
		"End with control-D or a dot on a line by itself.")
	scanner := bufio.NewScanner(os.Stdin)
	message := ""
	for scanner.Scan() {
		line := scanner.Text()
		if line == "." {
			break
		}
		message = message + line + "\n"
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return message, nil
}

func parseFlags() {
	haveMessage := false
	// TODO(davidben): To really be true to zwrite, check isatty
	// and, if not, set eofOnly to true.
	var i int
argLoop:
	for i = 1; i < len(os.Args); i++ {
		switch arg := os.Args[i]; arg {
		case "-a":
			auth = true
		case "-d":
			auth = false
		case "-t":
			expandTabs = false
		case "-l":
			eofOnly = true
		case "-u":
			instance = "URGENT"
		case "-m":
			haveMessage = true
			message = strings.Join(os.Args[i+1:], " ")
			break argLoop
		case "-s", "-c", "-i", "-r", "-S", "-O":
			if i+1 >= len(os.Args) {
				printUsage()
				os.Exit(1)
			}
			i++
			parseFlagArg(arg, os.Args[i])
		default:
			if len(arg) >= 1 && arg[0] == '-' {
				printUsage()
				os.Exit(1)
			}
			recipients = append(recipients, arg)
		}
	}

	// Normalize receipients.
	if len(recipients) == 0 {
		if class == "message" &&
			(instance == "personal" || instance == "URGENT") {
			fmt.Fprintln(os.Stderr, "No recipients specified.")
			printUsage()
			os.Exit(1)
		}
		recipients = []string{""}
	}
	if haveRealm {
		for i := range recipients {
			recipients[i] = recipients[i] + "@" + realm
		}
	}

	if !haveMessage {
		// Read message from stdin.
		var err error
		message, err = readMessage(eofOnly)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %s\n", err)
			os.Exit(1)
		}
	}

	if expandTabs {
		newMsg := []byte{}
		spaces := [8]byte{
			' ', ' ', ' ', ' ',
			' ', ' ', ' ', ' ',
		}
		off := 0
		for _, b := range []byte(message) {
			if b == '\t' {
				newMsg = append(newMsg, spaces[:8-off]...)
				off = 0
			} else {
				newMsg = append(newMsg, b)
				if b == '\n' {
					off = 0
				} else {
					off = (off + 1) % 8
				}
			}
		}
		message = string(newMsg)
	}
}

func main() {
	parseFlags()

	// Open a session.
	session, err := zephyr.DialSystemDefault()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()
	// Make sure the notice sink doesn't get stuck.
	// TODO(davidben): This is silly.
	go func() {
		for _ = range session.Messages() {
		}
	}()

	// Further normalize receipients.
	if !haveSender {
		sender = session.Sender()
	}
	for i := range recipients {
		if len(recipients[i]) != 0 && strings.Index(recipients[i], "@") < 0 {
			recipients[i] = recipients[i] + "@" + session.Realm()
		}
	}

	// Get tickets.
	ctx, err := krb5.NewContext()
	if err != nil {
		log.Fatal(err)
	}
	defer ctx.Free()
	for _, recipient := range recipients {
		// Construct the message.
		uid := session.MakeUID(time.Now())
		msg := &zephyr.Message{
			Header: zephyr.Header{
				Kind:  zephyr.ACKED,
				UID:   uid,
				Port:  session.Port(),
				Class: class, Instance: instance, OpCode: opcode,
				Sender:        sender,
				Recipient:     recipient,
				DefaultFormat: "http://mit.edu/df/",
				SenderAddress: session.LocalAddr().IP,
				Charset:       zephyr.CharsetUTF8,
				OtherFields:   nil,
			},
			Body: []string{signature, message},
		}
		sendTime := time.Now()
		var ack *zephyr.Notice
		var err error
		if auth {
			ack, err = session.SendMessage(ctx, msg)
		} else {
			ack, err = session.SendMessageUnauth(msg)
		}
		if err != nil {
			log.Printf("Send error: %v", err)
		} else {
			log.Printf("Received ack in %v: %v",
				time.Now().Sub(sendTime), ack)
		}
	}
}
