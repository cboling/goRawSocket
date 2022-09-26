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
	TPACKET_V2 = 1

	HOST_BYTE_SIZE  = 1
	HOST_SHORT_SIZE = 2
	HOST_INT_SIZE   = 4
	HOST_LONG_SIZE  = 8

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

var sizeOfTPacket2Hdr = unsafe.Sizeof(TPacket2Hdr{})

var (
	//	tpLenStart     int
	//	tpLenStop      int
	//	tpSnapLenStart int
	//	tpSnapLenStop  int
	//	tpMacStart     int
	//	tpMacStop      int
	//	tpNetStart     int
	//	tpNetStop      int
	//	tpSecStart     int
	//	tpSecStop      int
	//	tpNSecStart    int
	//	tpNSecStop     int
	//	tpTciStart     int
	//	tpTciStop      int
	//	tpTpidStart    int
	//	tpTpidStop     int
	//
	txStart int
)

func init() {
	//	tpLenStart = HOST_INT_SIZE
	//	tpLenStop = tpLenStart + HOST_INT_SIZE
	//
	//	tpSnapLenStart = tpLenStop
	//	tpSnapLenStop = tpSnapLenStart + HOST_INT_SIZE
	//
	//	tpMacStart = tpSnapLenStop
	//	tpMacStop = tpMacStart + HOST_SHORT_SIZE
	//
	//	tpNetStart = tpMacStop
	//	tpNetStop = tpNetStart + HOST_SHORT_SIZE
	//
	//	tpSecStart = tpNetStop
	//	tpSecStop = tpSecStart + HOST_INT_SIZE
	//
	//	tpNSecStart = tpSecStop
	//	tpNSecStop = tpNSecStart + HOST_INT_SIZE
	//
	//	tpTciStart = tpNSecStop
	//	tpTciStop = tpTciStart + HOST_SHORT_SIZE
	//
	//	tpTpidStart = tpTciStop
	//	tpTpidStop = tpTpidStart + HOST_SHORT_SIZE
	//
	//	txStart = tpTpidStop + (4 * HOST_BYTE_SIZE)
	txStart = int(sizeOfTPacket2Hdr)
	r := txStart % TPacketAlignment
	if r > 0 {
		txStart += TPacketAlignment - r
	}
}

func NewTPacket2Hdr(rawData []byte) *TPacket2Hdr { // unsafe.Pointer {
	tpHdr := (*TPacket2Hdr)(unsafe.Pointer(&rawData[0]))
	return tpHdr
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
	return HOST_INT_SIZE * 4
}
