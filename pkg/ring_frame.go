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

func PacketOffset() int {
	return txStart
}

type ringFrame struct {
	raw     []byte
	txStart []byte
	mb      uint32 // Memory barrier
	tpHdr   *TPacket2Hdr
}

func (rf *ringFrame) RxFrame(vlanEnabled bool) (nettypes.Frame, uint16, uint16) {
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
	frame := nettypes.NewFrame(rf.raw[start:])
	// fmt.Printf(frame.String(rf.tpSnapLen(), 0))
	return frame, rf.tpLen(), rf.tpSnapLen()
}

func (rf *ringFrame) macStart() uint16 {
	// TODO: Get rid of inet subdir
	return binary.LittleEndian.Uint16(rf.raw[tpMacStart:tpMacStop])
	//y := inet.Short(rf.raw[tpMacStart:tpMacStop])
	//if x == y {
	//	return y
	//}
	//return x
	//return inet.Short(rf.raw[tpMacStart:tpMacStop])
}

func (rf *ringFrame) tpLen() uint16 {
	return uint16(binary.LittleEndian.Uint32(rf.raw[tpLenStart:tpLenStop]))
	//return uint16(inet.Int(rf.raw[tpLenStart:tpLenStop]))
}

func (rf *ringFrame) setTpLen(v uint16) {
	binary.LittleEndian.PutUint32(rf.raw[tpLenStart:tpLenStop], uint32(v))
	//inet.PutInt(rf.raw[tpLenStart:tpLenStop], uint32(v))
}

func (rf *ringFrame) tpSnapLen() uint16 {
	return uint16(binary.LittleEndian.Uint32(rf.raw[tpSnapLenStart:tpSnapLenStop]))
}

func (rf *ringFrame) setTpSnapLen(v uint16) {
	// TODO: Get rid of inet subdir
	binary.LittleEndian.PutUint32(rf.raw[tpSnapLenStart:tpSnapLenStop], uint32(v))
}

func (rf *ringFrame) tpVlanTci() uint16 {
	return binary.LittleEndian.Uint16(rf.raw[tpTciStart:tpTciStop])
}

func (rf *ringFrame) tpVlanTpid() uint16 {
	return binary.LittleEndian.Uint16(rf.raw[tpTpidStart:tpTpidStop])
}

func (rf *ringFrame) vlan_valid() bool {
	return binary.LittleEndian.Uint32(rf.raw[0:HOST_INT_SIZE])&tpStatusVlanValid == tpStatusVlanValid
}

func (rf *ringFrame) tpid_valid() bool {
	return binary.LittleEndian.Uint32(rf.raw[0:HOST_INT_SIZE])&tpStatusVlanTpidValid == tpStatusVlanTpidValid
}

func (rf *ringFrame) rxReady() bool {
	oldRxReady := binary.LittleEndian.Uint32(rf.raw[0:HOST_INT_SIZE])&tpStatusUser == tpStatusUser && atomic.CompareAndSwapUint32(&rf.mb, 0, 1)
	return oldRxReady
}

func (rf *ringFrame) rxSet() {
	binary.LittleEndian.PutUint32(rf.raw[0:HOST_INT_SIZE], uint32(tpStatusKernel))
	// this acts as a memory barrier
	atomic.StoreUint32(&rf.mb, 0)
}

func (rf *ringFrame) txWrongFormat() bool {
	return binary.LittleEndian.Uint32(rf.raw[0:HOST_INT_SIZE])&tpStatusWrongFormat == tpStatusWrongFormat
}

func (rf *ringFrame) txReady() bool {
	return binary.LittleEndian.Uint32(rf.raw[0:HOST_INT_SIZE])&(tpStatusSendRequest|tpStatusSending) == 0
}

func (rf *ringFrame) txMBReady() bool {
	return atomic.CompareAndSwapUint32(&rf.mb, 0, 1)
}

func (rf *ringFrame) txSet() {
	binary.LittleEndian.PutUint32(rf.raw[0:HOST_INT_SIZE], uint32(tpStatusSendRequest))
}

func (rf *ringFrame) txSetMB() {
	atomic.StoreUint32(&rf.mb, 0)
}

func (rf *ringFrame) printRxStatus() {
	s := binary.LittleEndian.Uint32(rf.raw[0:HOST_INT_SIZE])
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
	s := binary.LittleEndian.Uint32(rf.raw[0:HOST_INT_SIZE])
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
