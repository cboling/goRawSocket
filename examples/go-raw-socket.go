/*
 * Copyright (c) 2022 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"fmt"
	rawsocket "github.com/cboling/goRawSocket/pkg"
	"github.com/cboling/goRawSocket/pkg/nettypes"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	exitChannel := make(chan int)
	rxChannel := make(chan []byte)
	defer close(exitChannel)
	defer close(rxChannel)

	//bpfString := "vlan"
	//bpfString := "vlan and ether proto 0xa8c8"
	bpfString := ""

	if sock, err := rawsocket.NewRawSocket("enp64s0",
		rawsocket.RxChannel(rxChannel),
		rawsocket.BerkleyPacketFilter(bpfString)); err == nil {

		if err = sock.Open(); err == nil {
			//defer sock.Close()

			sock.Listen(func(frame nettypes.Frame, frameLen, capturedLen uint16) nettypes.Frame {
				mT := frame.VLANTag()
				if mT == nettypes.Tagged || true {
					fmt.Printf(frame.String(capturedLen, 0))
				}
				return frame
			})
			waitForExit(exitChannel)
		} else {
			println("Failed to open RawSocket: %v", err)
		}
	} else {
		println("Failed to create RawSocket: %v", err)
	}
}

func processRxPackets(rxChannel chan []byte, exitChannel chan int) {
loop:
	for {
		select {
		case <-exitChannel:
			break loop
		case packet := <-rxChannel:
			println("Received a packet: %v octets", len(packet))
		default:
		}
	}
}

func waitForExit(exitChannel chan int) int {
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	go func() {
		s := <-signalChannel
		switch s {
		case syscall.SIGHUP,
			syscall.SIGINT,
			syscall.SIGTERM,
			syscall.SIGQUIT:
			exitChannel <- 0
		default:
			exitChannel <- 1
		}
	}()
	code := <-exitChannel
	return code
}