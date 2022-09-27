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

import "C"
import (
	"fmt"
	"github.com/cboling/goRawSocket/pkg/nettypes"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const invalidFd = -1

const (
	TPacketAlignment = 16

	MinimumFrameSize = TPacketAlignment << 7
	MaximumFrameSize = TPacketAlignment << 11
)

const (
	// Packet socket options
	PacketRxRing  = 5
	PacketVersion = 10
	PacketTxRing  = 13
	// TODO: Support for any of the following useful?
	PacketStatistics  = 6 /// Counts packets and drops
	PacketLoss        = 14
	PacketVnetHdr     = 15
	PacketTxTimestamp = 16
	PacketTimestamp   = 17

	/* poll events */
	pollIn  = 0x01
	pollOut = 0x04
	pollErr = 0x08
)

type RawSocket struct {
	netInterface string
	domain       int
	sockType     int
	proto        uint16
	fd           int
	bpfString    string
	bpf          []pcap.BPFInstruction
	rxChannel    chan nettypes.Frame

	done chan bool

	raw       []byte
	listening int32
	frameNum  int32
	frameSize uint16
	maxFrames uint
	rxEnabled bool
	rxFrames  []*ringFrame

	txEnabled bool
	//txLossDisabled bool
	txFrameSize    uint16
	txIndex        int32
	txWritten      int32
	txWrittenIndex int32
	txFrames       []*ringFrame
	vlanEnable     bool

	// TODO: Add statistics struct
}

// NewRawSocket initializes a new raw socket but does not open it
func NewRawSocket(intf string, opts ...Option) (*RawSocket, error) {
	sock := &RawSocket{
		netInterface: intf,
		fd:           invalidFd,
		domain:       syscall.AF_PACKET,
		sockType:     syscall.SOCK_RAW,
		proto:        syscall.ETH_P_ALL,
		frameSize:    2048,
		maxFrames:    128,
		rxEnabled:    true,
		txEnabled:    true,
		vlanEnable:   true,
		done:         make(chan bool),
	}
	for _, option := range opts {
		option(sock)
	}
	if sock.frameSize < MinimumFrameSize ||
		sock.frameSize > MaximumFrameSize ||
		(sock.frameSize&(sock.frameSize-1)) > 0 {
		return nil, fmt.Errorf("frame Size must be at least %d (MinimumFrameSize), be at most %d (MaximumFrameSize), and be a power of 2",
			MinimumFrameSize, MaximumFrameSize)
	}
	if sock.maxFrames < 16 && sock.maxFrames%8 == 0 {
		return nil, fmt.Errorf("max Total Frames must be at least 16, and be a multiple of 8")
	}
	if len(sock.bpfString) > 0 {
		var err error
		sock.bpf, err = pcap.CompileBPFFilter(layers.LinkTypeEthernet, int(sock.frameSize), sock.bpfString)
		if err != nil {
			return nil, err
		}
	}
	return sock, nil
}

func (sock *RawSocket) String() string {
	return "TODO" // TODO: Implement
}

func (sock *RawSocket) Open() error {
	if sock.fd != invalidFd {
		return nil
	}
	fd, err := syscall.Socket(sock.domain, sock.sockType, int(Htons(sock.proto)))
	if err == nil {
		if sock.bpf != nil {
			type SockFprog struct {
				Len     uint16
				PadCgo0 [6]byte
				Filter  *pcap.BPFInstruction
			}
			var program SockFprog
			program.Len = uint16(len(sock.bpf))
			program.Filter = (*pcap.BPFInstruction)(unsafe.Pointer(&sock.bpf[0]))

			if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
				uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_ATTACH_FILTER),
				uintptr(unsafe.Pointer(&program)), uintptr(unsafe.Sizeof(program)), 0); errno != 0 {
				println("Failed")
				return errno
			}
		}
		// Bind to the network interface
		err = syscall.BindToDevice(fd, sock.netInterface)
		if err != nil {
			_ = syscall.Close(fd)
			return err
		}
		if err = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, PacketVersion, TpacketV2); err != nil {
			_ = syscall.Close(fd)
			return err
		}
		// TODO: Have separate sizes/number-of-frames for RxRing and TxRing
		req := &TPacketReq{}
		pageSize := uint(os.Getpagesize())
		var frameSize uint
		if uint(sock.frameSize) < pageSize {
			frameSize = calculateLargestFrame(uint(sock.frameSize))
		} else {
			frameSize = (uint(sock.frameSize) / pageSize) * pageSize
		}
		req.frameSize = frameSize
		req.blockSize = req.frameSize * 8
		req.blockNum = sock.maxFrames / 8
		req.frameNum = (req.blockSize / req.frameSize) * req.blockNum
		reqP := req.getPointer()

		if sock.rxEnabled {
			_, _, e1 := syscall.Syscall6(uintptr(syscall.SYS_SETSOCKOPT), uintptr(fd),
				uintptr(syscall.SOL_PACKET), uintptr(PacketRxRing), uintptr(reqP),
				uintptr(req.size()), 0)
			if e1 != 0 {
				_ = syscall.Close(fd)
				return errnoErr(e1)
			}
		}
		if sock.txEnabled {
			_, _, e1 := syscall.Syscall6(uintptr(syscall.SYS_SETSOCKOPT), uintptr(fd),
				uintptr(syscall.SOL_PACKET), uintptr(PacketTxRing), uintptr(reqP),
				uintptr(req.size()), 0)
			if e1 != 0 {
				_ = syscall.Close(fd)
				return errnoErr(e1)
			}
		}
		size := req.blockSize * req.blockNum
		if sock.txEnabled && sock.rxEnabled {
			size *= 2
		}
		if sock.raw == nil {
			// Note: Kernel maps the RxRing first (if enabled) followed by the TxRing
			//       if enabled for this MMAP
			var bs []byte
			bs, err = syscall.Mmap(fd, int64(0), int(size), syscall.PROT_READ|
				syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_LOCKED|
				syscall.MAP_POPULATE)
			if err != nil {
				_ = syscall.Close(fd)
				return err
			}
			sock.raw = bs
		}
		sock.frameNum = int32(req.frameNum)
		sock.frameSize = uint16(req.frameSize)
		i := 0
		frameStart := 0
		if sock.rxEnabled {
			for i = 0; i < int(sock.frameNum); i++ {
				frameStart = i * int(sock.frameSize)
				data := sock.raw[frameStart : frameStart+int(sock.frameSize)]
				rxFrame := &ringFrame{
					raw:      data,
					tpHdr:    NewTPacket2Hdr(data),
					sockAddr: NewSockAddr(data[txStart:]),
				}
				sock.rxFrames = append(sock.rxFrames, rxFrame)
			}
		}
		if sock.txEnabled {
			sock.txFrameSize = sock.frameSize - uint16(txStart)
			sock.txWritten = 0
			sock.txWrittenIndex = -1
			for t := 0; t < int(sock.frameNum); t, i = t+1, i+1 {
				frameStart = i * int(sock.frameSize)
				data := sock.raw[frameStart : frameStart+int(sock.frameSize)]

				txFrame := &ringFrame{
					raw:     data,
					txStart: data[txStart:],
					tpHdr:   NewTPacket2Hdr(data),
				}
				sock.txFrames = append(sock.txFrames, txFrame)
			}
		}
		// If here, success
		sock.fd = fd
	}
	return err
}

func (sock *RawSocket) Close() {
	fd := sock.fd
	sock.fd = invalidFd
	if fd != invalidFd {
		defer syscall.Close(fd)

		// Signal any background thread
		if sock.listening != 0 {
			sock.done <- true
		}
	}
}

// MaxPackets returns the maximum amount of frame packets that can be written
func (sock *RawSocket) MaxPackets() int32 {
	return sock.frameNum
}

// MaxPacketSize returns the frame size in bytes
func (sock *RawSocket) MaxPacketSize() uint16 {
	return sock.txFrameSize
}

// WrittenPackets returns the amount of packets, written to the tx ring, that
// haven't been flushed.
func (sock *RawSocket) WrittenPackets() int32 {
	return atomic.LoadInt32(&sock.txWritten)
}

// Listen to all specified packets in the RX ring-buffer
func (sock *RawSocket) Listen(filter func(nettypes.Frame, uint32, uint32) nettypes.Frame) error {
	if !sock.rxEnabled {
		return fmt.Errorf("the RX ring is disabled on this socket")
	}
	if !atomic.CompareAndSwapInt32(&sock.listening, 0, 1) {
		return fmt.Errorf("there is already a listener on this socket")
	}
	pfd := &pollfd{}
	pfd.fd = sock.fd
	pfd.events = pollErr | pollIn
	pfd.revents = 0
	pfdP := uintptr(pfd.getPointer())
	rxIndex := int32(0)
	rf := sock.rxFrames[rxIndex]
	pollTimeout := -1
	pTOPointer := uintptr(unsafe.Pointer(&pollTimeout))
	for {
		for ; rf.rxReady(); rf = sock.rxFrames[rxIndex] {
			frame, tpLen, tpSnapLen := rf.RxFrame(sock.vlanEnable)

			// Send to listeners that may need to modify or validate the frame (decrypt, ...)
			// TODO: This functionality could be in the rxChannel as well or instead.
			if filter != nil && frame != nil {
				frame = filter(frame, tpLen, tpSnapLen)
			}
			if sock.rxChannel != nil && frame != nil {
				sock.rxChannel <- frame
			}
			rf.rxSet()
			rxIndex = (rxIndex + 1) % sock.frameNum
		}
		if sock.fd == invalidFd {
			break
		}
		_, _, e1 := syscall.Syscall(syscall.SYS_POLL, pfdP, uintptr(1), pTOPointer)
		if e1 != 0 {
			println("Error")
			//return e1
		}
	}
	return nil
}

// WriteToBuffer writes a raw frame in bytes to the TX ring buffer.
// The length of the frame must be specified.
func (sock *RawSocket) WriteToBuffer(buf []byte, l uint16) (int32, error) {
	if l > sock.txFrameSize {
		return -1, fmt.Errorf("the length of the write exceeds the size of the TX frame")
	}
	if l < 0 {
		return sock.CopyToBuffer(buf, uint16(len(buf)), copyFx)
	}
	return sock.CopyToBuffer(buf[:l], l, copyFx)
}

// CopyToBuffer is like WriteToBuffer, it writes a frame to the TX
// ring buffer. However, it can take a function argument, that will
// be passed the raw TX byes so that custom logic can be applied
// to copying the frame (for example, encrypting the frame).
func (sock *RawSocket) CopyToBuffer(buf []byte, l uint16, copyFx func(dst, src []byte, l uint16) uint16) (int32, error) {
	if !sock.txEnabled {
		return -1, fmt.Errorf("the TX ring is not enabled on this socket")
	}
	tx, txIndex, err := sock.getFreeTx()
	if err != nil {
		return -1, err
	}
	cL := copyFx(tx.txStart, buf, l)
	tx.setTpLen(uint32(cL))
	tx.setTpSnapLen(uint32(cL))
	written := atomic.AddInt32(&sock.txWritten, 1)
	if written == 1 {
		atomic.SwapInt32(&sock.txWrittenIndex, txIndex)
	}
	return txIndex, nil
}

// FlushFrames tells the kernel to flush all packets written
// to the TX ring buffer.n
func (sock *RawSocket) FlushFrames() (uint, error, []error) {
	if !sock.txEnabled {
		return 0, fmt.Errorf("the TX ring is not enabled on this socket, there is nothing to flush"), nil
	}
	var index int32
	for {
		index = atomic.LoadInt32(&sock.txWrittenIndex)
		if index == -1 {
			return 0, nil, nil
		}
		if atomic.CompareAndSwapInt32(&sock.txWrittenIndex, index, -1) {
			break
		}
	}
	written := atomic.SwapInt32(&sock.txWritten, 0)
	framesFlushed := uint(0)
	frameNum := sock.frameNum
	z := uintptr(0)
	for t, w := index, written; w > 0; w-- {
		sock.txFrames[t].txSet()
		t = (t + 1) % frameNum
	}
	if _, _, e1 := syscall.Syscall6(syscall.SYS_SENDTO, uintptr(sock.fd), z, z, z, z, z); e1 != 0 {
		return framesFlushed, e1, nil
	}
	var errs []error = nil
	for t, w := index, written; w > 0; w-- {
		tx := sock.txFrames[t]
		//if sock.txLossDisabled && tx.txWrongFormat() {
		//	errs = append(errs, txIndexError(t))
		//} else {
		//	framesFlushed++
		//}
		framesFlushed++
		tx.txSetMB()
		t = (t + 1) % frameNum
	}
	return framesFlushed, nil, errs
}

func (sock *RawSocket) getFreeTx() (*ringFrame, int32, error) {
	if atomic.LoadInt32(&sock.txWritten) == sock.frameNum {
		return nil, -1, fmt.Errorf("the tx ring buffer is full")
	}
	var txIndex int32
	for txIndex = atomic.LoadInt32(&sock.txIndex); !atomic.CompareAndSwapInt32(&sock.txIndex, txIndex,
		(txIndex+1)%int32(sock.frameNum)); txIndex = atomic.LoadInt32(&sock.txIndex) {
	}
	tx := sock.txFrames[txIndex]
	for !tx.txReady() {
		pfd := &pollfd{}
		pfd.fd = sock.fd
		pfd.events = pollErr | pollOut
		pfd.revents = 0
		timeout := -1
		_, _, e1 := syscall.Syscall(syscall.SYS_POLL, uintptr(pfd.getPointer()),
			uintptr(1), uintptr(unsafe.Pointer(&timeout)))
		if e1 != 0 {
			return nil, -1, e1
		}
	}
	for !tx.txMBReady() {
		runtime.Gosched()
	}
	return tx, txIndex, nil
}
