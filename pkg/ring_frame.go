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
	"encoding/binary"
	"fmt"
	"github.com/cboling/goRawSocket/pkg/nettypes"
	"sync/atomic"
)

type ringFrame struct {
	raw      []byte
	txStart  []byte
	mb       uint32 // Memory barrier
	tpHdr    *TPacket2Hdr
	sockAddr *SockAddr
}

func (rf *ringFrame) RxFrame(vlanEnabled bool) (nettypes.Frame, uint32, uint32) {
	start := int(rf.macStart())

	vlanPresent := vlanEnabled && rf.vlan_valid()
	if vlanPresent {
		vlanId := rf.tpVlanTci()
		vlanTpid := uint16(0x8100)
		if rf.tpid_valid() {
			vlanTpid = rf.tpVlanTpid()
		}
		vlanHdr := make([]byte, 4)
		binary.BigEndian.PutUint16(vlanHdr, vlanTpid)
		binary.BigEndian.PutUint16(vlanHdr[2:], vlanId)
		newLength := rf.tpSnapLen() + 4
		buf := make([]byte, newLength)
		copy(buf, rf.raw[start:start+12])
		copy(buf[12:], vlanHdr)
		copy(buf[16:], rf.raw[start+12:start+int(newLength)-4])

		frame := nettypes.NewFrame(buf)
		return frame, newLength, newLength
	}
	buf := make([]byte, rf.tpSnapLen())
	copy(buf, rf.raw[start:])
	frame := nettypes.NewFrame(buf)
	return frame, rf.tpLen(), rf.tpSnapLen()
}

func (rf *ringFrame) macStart() uint16 {
	return rf.tpHdr.TpMac
}

func (rf *ringFrame) tpLen() uint32 {
	return rf.tpHdr.TpLen
}

func (rf *ringFrame) setTpLen(value uint32) {
	rf.tpHdr.TpLen = value
}

func (rf *ringFrame) tpSnapLen() uint32 {
	return rf.tpHdr.TpSnapLen
}

func (rf *ringFrame) setTpSnapLen(value uint32) {
	rf.tpHdr.TpSnapLen = value
}

func (rf *ringFrame) tpVlanTci() uint16 {
	return rf.tpHdr.TpVlanTci
}

func (rf *ringFrame) tpVlanTpid() uint16 {
	return rf.tpHdr.TpVlanTpid
}

func (rf *ringFrame) vlan_valid() bool {
	return rf.tpHdr.vlanValid()
}

func (rf *ringFrame) tpid_valid() bool {
	return rf.tpHdr.tpidValid()
}

func (rf *ringFrame) rxReady() bool {
	if rf.tpHdr.rxReady() && rf.mb == 1 {
		fmt.Println("Ready but memory block already set")
	}
	ready := rf.tpHdr.rxReady() && atomic.CompareAndSwapUint32(&rf.mb, 0, 1)

	if ready {
		start := int(rf.macStart())
		pkt := rf.raw[start:]
		if pkt[0] == 0 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 && pkt[4] == 0 && pkt[5] == 0 {
			fmt.Println("") // Ready but zero destination address
			fmt.Println("")
		}
	}
	return ready
}

func (rf *ringFrame) rxSet() {
	rf.tpHdr.TpLen = 0
	rf.tpHdr.TpSnapLen = 0
	rf.tpHdr.TpStatus = tpStatusKernel
	atomic.StoreUint32(&rf.mb, 0) // this acts as a memory barrier
}

func (rf *ringFrame) txWrongFormat() bool {
	return rf.tpHdr.txWrongFormat()
}

func (rf *ringFrame) txReady() bool {
	return rf.tpHdr.txReady()
}

func (rf *ringFrame) txMBReady() bool {
	return atomic.CompareAndSwapUint32(&rf.mb, 0, 1)
}

func (rf *ringFrame) txSet() {
	rf.tpHdr.txSet()
}

func (rf *ringFrame) txSetMB() {
	atomic.StoreUint32(&rf.mb, 0)
}

func (rf *ringFrame) printRxStatus() {
	s := rf.tpHdr.TpStatus
	fmt.Printf("RX STATUS :")
	if s == 0 {
		fmt.Printf(" Kernel")
	}
	if tpStatusUser&s > 0 {
		fmt.Printf(" User")
	}
	if tpStatusCopy&s > 0 {
		fmt.Printf(" Copy")
	}
	if tpStatusLosing&s > 0 {
		fmt.Printf(" Losing")
	}
	if tpStatusCSumNotReady&s > 0 {
		fmt.Printf(" CSUM-NotReady")
	}
	if tpStatusVlanValid&s > 0 {
		fmt.Printf(" VlanValid")
	}
	if tpStatusBlkTMO&s > 0 {
		fmt.Printf(" BlkTMO")
	}
	if tpStatusVlanValid&s > 0 {
		fmt.Printf(" VlanValid")
	}
	if tpStatusVlanTpidValid&s > 0 {
		fmt.Printf(" VlanTPIDValid")
	}
	if tpStatusCSumValid&s > 0 {
		fmt.Printf(" CSUM-Valid")
	}
	rf.printRxTxStatus(s)
	fmt.Printf("\n")
}

func (rf *ringFrame) printTxStatus() {
	s := rf.tpHdr.TpStatus
	fmt.Printf("TX STATUS :")
	if s == 0 {
		fmt.Printf(" Available")
	}
	if s&tpStatusSendRequest > 0 {
		fmt.Printf(" SendRequest")
	}
	if s&tpStatusSending > 0 {
		fmt.Printf(" Sending")
	}
	if s&tpStatusWrongFormat > 0 {
		fmt.Printf(" WrongFormat")
	}
	rf.printRxTxStatus(s)
	fmt.Printf("\n")
}

func (rf *ringFrame) printRxTxStatus(s uint32) {
	if s&tpStatusTSSoftware > 0 {
		fmt.Printf(" Software")
	}
	if s&tpStatusTSRawHardware > 0 {
		fmt.Printf(" Hardware")
	}
}
