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
	"sync/atomic"
)

type ringFrame struct {
	raw      []byte
	txStart  []byte
	mb       uint32 // Memory barrier
	tpHdr    *TPacket2Hdr
	sockAddr *SockAddr
}

func (rf *ringFrame) macStart() uint16 {
	return rf.tpHdr.TpMac
}

func (rf *ringFrame) vlanAdjust() {
	if rf.vlanValid() {
		// Adjust for VLAN header size
		rf.tpHdr.TpMac -= 4
		rf.tpHdr.TpSnapLen += 4
		rf.tpHdr.TpLen += 4

		// Move Dst/Src MAC up 4 bytes and add vlan header (keeping original MMAP buffer)
		// and return that instead.  We reserved 4 octets in the ring buffer to accomidate
		// for this
		start := int(rf.macStart())
		for offset := 0; offset < 12; offset++ {
			rf.raw[start+offset] = rf.raw[start+offset+1]
		}
		// Insert VLAN Header
		vlanTpid := uint16(0x8100)
		if rf.tpidValid() {
			vlanTpid = rf.tpVlanTpid()
		}
		binary.BigEndian.PutUint16(rf.raw[start+12:], vlanTpid)
		binary.BigEndian.PutUint16(rf.raw[start+14:], rf.tpVlanTci())

		// Tweak TPacket Rx Status field since buffer now has VID
		rf.tpHdr.TpStatus &= ^uint32(tpStatusVlanValid | tpStatusVlanTpidValid)
	}
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

func (rf *ringFrame) vlanValid() bool {
	return rf.tpHdr.vlanValid()
}

func (rf *ringFrame) tpidValid() bool {
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
