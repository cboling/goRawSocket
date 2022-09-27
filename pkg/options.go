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

package rawsocket

import "github.com/cboling/goRawSocket/pkg/nettypes"

type Option func(*RawSocket)

func Domain(domain int) Option {
	return func(args *RawSocket) {
		args.domain = domain
	}
}

func Protocol(proto uint16) Option {
	return func(args *RawSocket) {
		args.proto = proto
	}
}

func RxChannel(channel chan nettypes.Frame) Option {
	return func(args *RawSocket) {
		args.rxChannel = channel
	}
}

func MaxFrameSize(maxSize uint16) Option {
	return func(args *RawSocket) {
		args.frameSize = maxSize
	}
}

func MaxTotalFrames(maxFrames uint) Option {
	return func(args *RawSocket) {
		args.maxFrames = maxFrames
	}
}

func RxEnable(enable bool) Option {
	return func(args *RawSocket) {
		args.rxEnabled = enable
	}
}

func TxEnable(enable bool) Option {
	return func(args *RawSocket) {
		args.txEnabled = enable
	}
}

func VlanEnable(enable bool) Option {
	return func(args *RawSocket) {
		args.vlanEnable = enable
	}
}

func BerkleyPacketFilter(bpf string) Option {
	return func(args *RawSocket) {
		args.bpfString = bpf
	}
}
