package deprecated

import (
	"fmt"
	"github.com/cboling/goRawSocket/pkg/inet"
	"github.com/cboling/goRawSocket/pkg/nettypes"
)

type UDPPacket []byte

func (t UDPPacket) IPProtocol() IPProtocol {
	return UDP
}

func (t UDPPacket) Bytes() []byte {
	return t
}

func (t UDPPacket) String(frameLen uint16, indent int) string {
	return fmt.Sprintf(nettypes.padLeft("UDP Len      : %d\n", "\t", indent), frameLen) +
		fmt.Sprintf(nettypes.padLeft("Source Port  : %d\n", "\t", indent), t.SourcePort()) +
		fmt.Sprintf(nettypes.padLeft("Dest Port    : %d\n", "\t", indent), t.DestinationPort()) +
		fmt.Sprintf(nettypes.padLeft("Checksum     : %02x\n", "\t", indent), t.Checksum()) +
		fmt.Sprintf(nettypes.padLeft("CalcChecksum : %02x\n", "\t", indent), inet.HToNSFS(t.CalculateChecksum()))
}

func (t UDPPacket) SourcePort() uint16 {
	return inet.NToHS(t[0:2])
}

func (t UDPPacket) DestinationPort() uint16 {
	return inet.NToHS(t[2:4])
}

func (t UDPPacket) Length() uint16 {
	return inet.NToHS(t[4:6])
}

func (t UDPPacket) SetLength(v uint16) {
	inet.PutShort(t[4:6], v)
}

func (t UDPPacket) Checksum() uint16 {
	return inet.NToHS(t[6:8])
}

func (t UDPPacket) CalculateChecksum() uint16 {
	var cs uint32
	i := 0
	fl := t.Length()
	for ; fl > 1; i, fl = i+2, fl-2 {
		cs += uint32(inet.HostByteOrder.Uint16(t[i : i+2]))
		if cs&0x80000000 > 0 {
			cs = (cs & 0xffff) + (cs >> 16)
		}
	}
	if fl > 0 {
		cs += uint32(uint8(t[i]))
	}
	for cs>>16 > 0 {
		cs = (cs & 0xffff) + (cs >> 16)
	}
	return ^uint16(cs)
}

func (t UDPPacket) SetChecksum(v uint16) {
	inet.PutShort(t[6:8], v)
}

func (t UDPPacket) Payload() ([]byte, uint16) {
	return t[8:], 8
}
