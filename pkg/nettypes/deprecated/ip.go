package deprecated

import (
	"fmt"
	"github.com/cboling/goRawSocket/pkg/nettypes"
	"net"

	"github.com/cboling/goRawSocket/pkg/inet"
)

type IPProtocol uint8

const (
	HOPOPT = IPProtocol(0x00)
	ICMP   = IPProtocol(0x01)
	IGMP   = IPProtocol(0x02)
	GGP    = IPProtocol(0x03)
	IPinIP = IPProtocol(0x04)
	ST     = IPProtocol(0x05)
	TCP    = IPProtocol(0x06)
	UDP    = IPProtocol(0x11)
)

func (p IPProtocol) String() string {
	switch p {
	case HOPOPT:
		return "HOPOPT"
	case ICMP:
		return "ICMP"
	case IGMP:
		return "IGMP"
	case GGP:
		return "GGP"
	case IPinIP:
		return "IPinIP"
	case ST:
		return "ST"
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	default:
		return fmt.Sprintf("%x", byte(p))
	}
}

type IPv4Packet []byte

func (i IPv4Packet) EthType() nettypes.EthType {
	return nettypes.IPv4
}

func (i IPv4Packet) Bytes() []byte {
	return i
}

func (i IPv4Packet) String(frameLen uint16, indent int) string {
	return fmt.Sprintf(nettypes.padLeft("IP Len   : %d\n", "\t", indent), frameLen) +
		fmt.Sprintf(nettypes.padLeft("Version  : %d\n", "\t", indent), i.Version()) +
		fmt.Sprintf(nettypes.padLeft("IHL      : %d\n", "\t", indent), i.IHL()) +
		fmt.Sprintf(nettypes.padLeft("Length   : %d\n", "\t", indent), i.Length()) +
		fmt.Sprintf(nettypes.padLeft("Id       : %d\n", "\t", indent), i.Id()) +
		fmt.Sprintf(nettypes.padLeft("Flags    : %s\n", "\t", indent), i.FlagsString()) +
		fmt.Sprintf(nettypes.padLeft("Frag Off : %d\n", "\t", indent), i.FragmentOffset()) +
		fmt.Sprintf(nettypes.padLeft("TTL HC   : %d\n", "\t", indent), i.TTLHopCount()) +
		fmt.Sprintf(nettypes.padLeft("Protocol : %s\n", "\t", indent), i.Protocol()) +
		fmt.Sprintf(nettypes.padLeft("Checksum : %02x\n", "\t", indent), i.Checksum()) +
		fmt.Sprintf(nettypes.padLeft("Calcsum  : %02x\n", "\t", indent), inet.HToNSFS(i.CalculateChecksum())) +
		fmt.Sprintf(nettypes.padLeft("SourceIP : %s\n", "\t", indent), i.SourceIP()) +
		fmt.Sprintf(nettypes.padLeft("DestIP   : %s\n", "\t", indent), i.DestinationIP()) +
		i.PayloadString(frameLen, indent)
}

func (i IPv4Packet) PayloadString(frameLen uint16, indent int) string {
	p, off := i.Payload()
	frameLen -= off
	indent++
	switch i.Protocol() {
	case TCP:
		return TCPPacket(p).String(frameLen, indent, i.SourceIP(), i.DestinationIP())
	case UDP:
		return UDPPacket(p).String(frameLen, indent)
	case ICMP:
		return ICMPPacket(p).String(frameLen, indent)
	default:
		indent--
		return nettypes.padLeft("unrecognized ip protocol...\n", "\t", indent)
	}
}

func (i IPv4Packet) Version() uint8 {
	return uint8(i[0] >> 4)
}

func (i IPv4Packet) IHL() uint8 {
	return uint8(i[0] & 0x0f)
}

func (i IPv4Packet) Length() uint16 {
	return inet.NToHS(i[2:4])
}

func (i IPv4Packet) Id() uint16 {
	return inet.NToHS(i[4:6])
}

func (i IPv4Packet) Flags() uint8 {
	return uint8(i[6] >> 5)
}

func (i IPv4Packet) FlagsString() string {
	s := ""
	f := i.Flags()
	if f&0x01 == 0x01 {
		s += "MF"
	}
	if f&0x02 == 0x02 {
		s += "DF"
	}
	return s
}

func (i IPv4Packet) FragmentOffset() uint16 {
	return inet.NToHS([]byte{i[6] & 0x1f, i[7]})
}

func (i IPv4Packet) TTLHopCount() uint8 {
	return uint8(i[8])
}

func (i IPv4Packet) Protocol() IPProtocol {
	return IPProtocol(i[9])
}

func (i IPv4Packet) Checksum() uint16 {
	return inet.NToHS(i[10:12])
}

func (i IPv4Packet) CalculateChecksum() uint16 {
	cs := uint32(inet.HostByteOrder.Uint16(i[0:2])) +
		uint32(inet.HostByteOrder.Uint16(i[2:4])) +
		uint32(inet.HostByteOrder.Uint16(i[4:6])) +
		uint32(inet.HostByteOrder.Uint16(i[6:8])) +
		uint32(inet.HostByteOrder.Uint16(i[8:10])) +
		uint32(inet.HostByteOrder.Uint16(i[12:14])) +
		uint32(inet.HostByteOrder.Uint16(i[14:16])) +
		uint32(inet.HostByteOrder.Uint16(i[16:18])) +
		uint32(inet.HostByteOrder.Uint16(i[18:20]))
	index := 20
	for t, l := 0, int(i.IHL()-5); t < l; t++ {
		cs += uint32(inet.HostByteOrder.Uint16(i[index : index+2]))
		index += 2
		cs += uint32(inet.HostByteOrder.Uint16(i[index : index+2]))
		index += 2
	}
	for cs>>16 > 0 {
		cs = (cs & 0xffff) + (cs >> 16)
	}
	return ^uint16(cs)
}

func (i IPv4Packet) PacketCorrupt() bool {
	return i.Checksum() == i.CalculateChecksum()
}

func (i IPv4Packet) SourceIP() net.IP {
	return net.IP(i[12:16])
}

func (i IPv4Packet) DestinationIP() net.IP {
	return net.IP(i[16:20])
}

func (i IPv4Packet) Payload() ([]byte, uint16) {
	off := uint16(i.IHL() * 4)
	return i[off:], off
}
