package deprecated

import (
	"fmt"
	"github.com/cboling/goRawSocket/pkg/nettypes"
	"net"

	"github.com/cboling/goRawSocket/pkg/inet"
)

type ICMPType uint8

const (
	EchoReply              = ICMPType(0x00)
	DestinationUnreachable = ICMPType(0x03)
	RedirectMessage        = ICMPType(0x05)
	EchoRequest            = ICMPType(0x08)
	RouterAdvertisement    = ICMPType(0x09)
	RouterSolicitation     = ICMPType(0x0a)
	TimeExceeded           = ICMPType(0x0b)
	ParameterProblem       = ICMPType(0x0c)
	Timestamp              = ICMPType(0x0d)
	TimestampReply         = ICMPType(0x0e)
)

func (i ICMPType) String() string {
	switch i {
	case EchoReply:
		return "EchoReply"
	case DestinationUnreachable:
		return "DestinationUnreachable"
	case RedirectMessage:
		return "RedirectMessage"
	case EchoRequest:
		return "EchoRequest"
	case RouterAdvertisement:
		return "RouterAdvertisement"
	case RouterSolicitation:
		return "RouterSolicitation"
	case TimeExceeded:
		return "TimeExceeded"
	case ParameterProblem:
		return "ParameterProblem"
	case Timestamp:
		return "Timestamp"
	case TimestampReply:
		return "TimestampReply"
	default:
		return fmt.Sprintf("unkown type:%x", uint8(i))
	}
}

type ICMPCode uint8

func (i ICMPCode) String(typ ICMPType) string {
	switch typ {
	case EchoReply:
		return "EchoReply"
	case DestinationUnreachable:
		switch i {
		case 0x00:
			return "Destination network unreachable"
		case 0x01:
			return "Destination host unreachable"
		case 0x02:
			return "Destination protocol unreachable"
		case 0x03:
			return "Destination port unreachable"
		case 0x04:
			return "Fragmentation required, and DF flag set"
		case 0x05:
			return "Source route failed"
		case 0x06:
			return "Destination network unknown"
		case 0x07:
			return "Destination host unknown"
		case 0x08:
			return "Source host isolated"
		case 0x09:
			return "Network administratively prohibited"
		case 0x0a:
			return "Host administratively prohibited"
		case 0x0b:
			return "Network unreachable for ToS"
		case 0x0c:
			return "Host unreachable for ToS"
		case 0x0d:
			return "Communication administratively prohibited"
		case 0x0e:
			return "Host Precedence Violation"
		case 0x0f:
			return "Precedence cutoff in effect"
		}
	case RedirectMessage:
		switch i {
		case 0x00:
			return "Redirect Datagram for the Network"
		case 0x01:
			return "Redirect Datagram for the Host"
		case 0x02:
			return "Redirect Datagram for the ToS & network"
		case 0x03:
			return "Redirect Datagram for the ToS & host"
		default:
			return fmt.Sprintf("incorrect code set: %x", uint8(i))
		}
	case EchoRequest:
		return "EchoRequest"
	case RouterAdvertisement:
		return "RouterAdvertisement"
	case RouterSolicitation:
		return "RouterSolicitation"
	case TimeExceeded:
		switch i {
		case 0x00:
			return "TTL expired in transit"
		case 0x01:
			return "Fragment reassembly time exceeded"
		default:
			return fmt.Sprintf("incorrect code set: %x", uint8(i))
		}
	case ParameterProblem:
		switch i {
		case 0x00:
			return "Pointer indicates the error"
		case 0x01:
			return "Missing a required option"
		case 0x02:
			return "Bad length"
		default:
			return fmt.Sprintf("incorrect code set: %x", uint8(i))
		}
	case Timestamp:
		return "Timestamp"
	case TimestampReply:
		return "TimestampReply"
	}
	return fmt.Sprintf("unkown code:%x", uint8(i))
}

type ICMPPacket []byte

func (p ICMPPacket) IPProtocol() IPProtocol {
	return ICMP
}

func (p ICMPPacket) Bytes() []byte {
	return p
}

func (p ICMPPacket) String(frameLen uint16, indent int) string {
	typ := p.Type()
	pay, _ := p.Payload()
	ps := pay.String(typ, indent, frameLen-4)
	s := fmt.Sprintf(nettypes.padLeft("ICMP Len     : %d\n", "\t", indent), frameLen) +
		fmt.Sprintf(nettypes.padLeft("Type         : %s\n", "\t", indent), typ) +
		fmt.Sprintf(nettypes.padLeft("Code         : %s\n", "\t", indent), p.Code().String(typ)) +
		fmt.Sprintf(nettypes.padLeft("Checksum     : %02x\n", "\t", indent), p.Checksum()) +
		fmt.Sprintf(nettypes.padLeft("CalcChecksum : %02x\n", "\t", indent), inet.HToNSFS(p.CalculateChecksum(frameLen)))
	if len(ps) > 0 {
		s += fmt.Sprintf(nettypes.padLeft("Payload      :\n%s", "\t", indent), ps)
	}
	return s
}

func (p ICMPPacket) Type() ICMPType {
	return ICMPType(p[0])
}

func (p ICMPPacket) Code() ICMPCode {
	return ICMPCode(p[1])
}

func (p ICMPPacket) Checksum() uint16 {
	return inet.NToHS(p[2:4])
}

func (p ICMPPacket) CalculateChecksum(frameLen uint16) uint16 {
	cs := uint32(inet.HostByteOrder.Uint16(p[0:2])) +
		uint32(inet.HostByteOrder.Uint16(p[4:6])) +
		uint32(inet.HostByteOrder.Uint16(p[6:8]))
	frameLen -= 8
	i := 8
	for ; frameLen > 1; i, frameLen = i+2, frameLen-2 {
		cs += uint32(inet.HostByteOrder.Uint16(p[i : i+2]))
		if cs&0x80000000 > 0 {
			cs = (cs & 0xffff) + (cs >> 16)
		}
	}
	if frameLen > 0 {
		cs += uint32(uint8(p[i]))
	}
	for cs>>16 > 0 {
		cs = (cs & 0xffff) + (cs >> 16)
	}
	return ^uint16(cs)
}

func (p ICMPPacket) Payload() (ICMPPacketayload, uint16) {
	return ICMPPacketayload(p[4:]), 4
}

type ICMPPacketayload []byte

func (pay ICMPPacketayload) String(typ ICMPType, indent int, length uint16) string {
	indent++
	switch typ {
	case RedirectMessage:
		return fmt.Sprintf(nettypes.padLeft("IP Addr : %s\n", "\t", indent), net.IP(pay[4:8]).String())
	case Timestamp:
		fallthrough
	case TimestampReply:
		return fmt.Sprintf(nettypes.padLeft("Identifier  : %d\n", "\t", indent), inet.NToHI(pay[4:6])) +
			fmt.Sprintf(nettypes.padLeft("Seq Number  : %d\n", "\t", indent), inet.NToHI(pay[6:8])) +
			fmt.Sprintf(nettypes.padLeft("Origin TS   : %d\n", "\t", indent), inet.NToHI(pay[8:12])) +
			fmt.Sprintf(nettypes.padLeft("Receive TS  : %d\n", "\t", indent), inet.NToHI(pay[12:16])) +
			fmt.Sprintf(nettypes.padLeft("Transmit TS : %d\n", "\t", indent), inet.NToHI(pay[16:20]))
	default:
		s := nettypes.padLeft("", "\t", indent)
		for i := uint16(0); i < length; i++ {
			s += fmt.Sprintf("%02x ", pay[i])
		}
		s += "\n"
		return s
	}
}
