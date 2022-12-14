//go:build (linux || darwin || freebsd || netbsd || openbsd || plan9 || solaris) && (amd64 || arm64 || ppc64 || ppc64le || mips64 || mips64le)
// +build linux darwin freebsd netbsd openbsd plan9 solaris
// +build amd64 arm64 ppc64 ppc64le mips64 mips64le

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

import (
	"unsafe"
)

const (
	HostByteSize  = 1
	HostShortSize = 2
	HostIntSize   = 4
	HostLongSize  = 8

	/* rx status */
	tpStatusKernel        = 0
	tpStatusUser          = 1 << 0
	tpStatusCopy          = 1 << 1
	tpStatusLosing        = 1 << 2
	tpStatusCSumNotReady  = 1 << 3
	tpStatusVlanValid     = 1 << 4 /* auxdata has valid tp_vlan_tci */
	tpStatusBlkTMO        = 1 << 5
	tpStatusVlanTpidValid = 1 << 6 /* auxdata has valid tp_vlan_tpid */
	tpStatusCSumValid     = 1 << 7

	/* tx status */
	tpStatusAvailable   = 0
	tpStatusSendRequest = 1 << 0
	tpStatusSending     = 1 << 1
	tpStatusWrongFormat = 1 << 2

	/* tx and rx status */
	tpStatusTSSoftware    = 1 << 29
	tpStatusTSRawHardware = 1 << 31
)

type TPacketVersion int

const TpacketV2 TPacketVersion = 1
const TpacketV3 TPacketVersion = 2

type TPacket2Hdr struct {
	TpStatus   uint32
	TpLen      uint32
	TpSnapLen  uint32
	TpMac      uint16
	TpNet      uint16
	TpSec      uint32
	TpNsec     uint32
	TpVlanTci  uint16
	TpVlanTpid uint16
	tPPadding1 uint8
	tPPadding2 uint8
	tPPadding3 uint8
	tPPadding4 uint8
}

// #nosec
var sizeOfTPacket2Hdr = unsafe.Sizeof(TPacket2Hdr{})
var txStart int

func init() {
	txStart = int(sizeOfTPacket2Hdr)
	r := txStart % TPacketAlignment
	if r > 0 {
		txStart += TPacketAlignment - r
	}
}

func NewTPacket2Hdr(rawData []byte) *TPacket2Hdr { // unsafe.Pointer {
	// #nosec
	return (*TPacket2Hdr)(unsafe.Pointer(&rawData[0]))
}

func (hdr *TPacket2Hdr) vlanValid() bool {
	return hdr.TpStatus&tpStatusVlanValid == tpStatusVlanValid
}

func (hdr *TPacket2Hdr) tpidValid() bool {
	return hdr.TpStatus&tpStatusVlanTpidValid == tpStatusVlanTpidValid
}

func (hdr *TPacket2Hdr) rxReady() bool {
	return hdr.TpStatus&tpStatusUser == tpStatusUser
}

func (hdr *TPacket2Hdr) txWrongFormat() bool {
	return hdr.TpStatus&tpStatusWrongFormat == tpStatusWrongFormat
}

func (hdr *TPacket2Hdr) txReady() bool {
	return hdr.TpStatus&(tpStatusSendRequest|tpStatusSending) == 0
}

func (hdr *TPacket2Hdr) txSet() {
	hdr.TpStatus = uint32(tpStatusSendRequest)
}

type TPacketReq struct {
	blockSize uint // Minimal size of contiguous block
	blockNum  uint // Number of blocks
	frameSize uint // Size of frame
	frameNum  uint // Total number of frames
}

func (req *TPacketReq) getPointer() unsafe.Pointer {
	// #nosec
	return unsafe.Pointer(&(struct {
		blockSize,
		blockNum,
		frameSize,
		frameNum uint32
	}{
		uint32(req.blockSize),
		uint32(req.blockNum),
		uint32(req.frameSize),
		uint32(req.frameNum),
	}))
}

func (req *TPacketReq) size() int {
	return HostIntSize * 4
}

type SockAddr struct {
	sllFamily   uint16   // Always AF_PACKET
	sllProtocol uint16   // Physical-layer protocol  (BigEndian format)
	sllIfIndex  uint32   // Interface number
	sllHaType   uint16   // ARP hardware type. Ethernet is hardware type 1
	sllPktType  uint8    // Packet type
	sllHaLen    uint8    // Length of address
	sllAddr     [8]uint8 // Physical-layer address
}

/* Packet types */
const (
	PacketHost      = 0 // To us
	PacketBroadcast = 1 // To all
	PacketMulticast = 2 // To group
	PacketOtherHost = 3 // To someone else
	PacketOutgoing  = 4 // Outgoing of any type
	PacketLoopback  = 5 // MC/BRD frame looped back
	PacketUser      = 6 // To user space
	PacketFastRoute = 6 // Fastrouted frame
	PacketKernel    = 7 // To kernel space
	// Unused, PacketLoopback and PacketFastRoute are invisible to user space
)

func NewSockAddr(rawData []byte) *SockAddr {
	// #nosec
	sockAddr := (*SockAddr)(unsafe.Pointer(&rawData[0]))
	return sockAddr
}

func Family(sa *SockAddr) uint16 {
	return sa.sllFamily
}

func SockProtocol(sa *SockAddr) uint16 {
	return sa.sllProtocol
}

func Ifindex(sa *SockAddr) uint32 {
	return sa.sllIfIndex
}

func PacketType(sa *SockAddr) uint8 {
	return sa.sllPktType
}

func AddrType(sa *SockAddr) uint16 {
	return sa.sllHaType
}

func AddrLen(sa *SockAddr) uint8 {
	return sa.sllHaLen
}

func Addr(sa *SockAddr) []byte {
	return sa.sllAddr[:AddrLen(sa)]
}
