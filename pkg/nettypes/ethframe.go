package nettypes

import (
	"encoding/binary"
	"fmt"
	"net"
)

type EthType [2]byte

var (
	All                 = EthType{0x00, 0x03}
	IPv4                = EthType{0x08, 0x00}
	ARP                 = EthType{0x08, 0x06}
	WakeOnLAN           = EthType{0x08, 0x42}
	TRILL               = EthType{0x22, 0xF3}
	DECnetPhase4        = EthType{0x60, 0x03}
	RARP                = EthType{0x80, 0x35}
	AppleTalk           = EthType{0x80, 0x9B}
	AARP                = EthType{0x80, 0xF3}
	IPX1                = EthType{0x81, 0x37}
	IPX2                = EthType{0x81, 0x38}
	QNXQnet             = EthType{0x82, 0x04}
	IPv6                = EthType{0x86, 0xDD}
	EthernetFlowControl = EthType{0x88, 0x08}
	IEEE802_3           = EthType{0x88, 0x09}
	CobraNet            = EthType{0x88, 0x19}
	MPLSUnicast         = EthType{0x88, 0x47}
	MPLSMulticast       = EthType{0x88, 0x48}
	PPPoEDiscovery      = EthType{0x88, 0x63}
	PPPoESession        = EthType{0x88, 0x64}
	JumboFrames         = EthType{0x88, 0x70}
	HomePlug1_0MME      = EthType{0x88, 0x7B}
	IEEE802_1X          = EthType{0x88, 0x8E}
	PROFINET            = EthType{0x88, 0x92}
	HyperSCSI           = EthType{0x88, 0x9A}
	AoE                 = EthType{0x88, 0xA2}
	EtherCAT            = EthType{0x88, 0xA4}
	EthernetPowerlink   = EthType{0x88, 0xAB}
	LLDP                = EthType{0x88, 0xCC}
	SERCOS3             = EthType{0x88, 0xCD}
	HomePlugAVMME       = EthType{0x88, 0xE1}
	MRP                 = EthType{0x88, 0xE3}
	MACSec              = EthType{0x88, 0xE5}
	IEEE1588            = EthType{0x88, 0xF7}
	IEEE802_1ag         = EthType{0x89, 0x02}
	FCoE                = EthType{0x89, 0x06}
	FCoEInit            = EthType{0x89, 0x14}
	RoCE                = EthType{0x89, 0x15}
	CTP                 = EthType{0x90, 0x00}
	VeritasLLT          = EthType{0xCA, 0xFE}
	IEEE1904_2          = EthType{0xA8, 0xC8}
)

func (e EthType) String() string {
	switch e {
	case All:
		return "All"
	case IPv4:
		return "IPv4"
	case ARP:
		return "ARP"
	case WakeOnLAN:
		return "WakeOnLAN"
	case TRILL:
		return "TRILL"
	case DECnetPhase4:
		return "DECnetPhase4"
	case RARP:
		return "RARP"
	case AppleTalk:
		return "AppleTalk"
	case AARP:
		return "AARP"
	case IPX1:
		return "IPX1"
	case IPX2:
		return "IPX2"
	case QNXQnet:
		return "QNXQnet"
	case IPv6:
		return "IPv6"
	case EthernetFlowControl:
		return "EthernetFlowControl"
	case IEEE802_3:
		return "IEEE802_3"
	case CobraNet:
		return "CobraNet"
	case MPLSUnicast:
		return "MPLSUnicast"
	case MPLSMulticast:
		return "MPLSMulticast"
	case PPPoEDiscovery:
		return "PPPoEDiscovery"
	case PPPoESession:
		return "PPPoESession"
	case JumboFrames:
		return "JumboFrames"
	case HomePlug1_0MME:
		return "HomePlug1_0MME"
	case IEEE802_1X:
		return "IEEE802_1X"
	case PROFINET:
		return "PROFINET"
	case HyperSCSI:
		return "HyperSCSI"
	case AoE:
		return "AoE"
	case EtherCAT:
		return "EtherCAT"
	case EthernetPowerlink:
		return "EthernetPowerlink"
	case LLDP:
		return "LLDP"
	case SERCOS3:
		return "SERCOS3"
	case HomePlugAVMME:
		return "HomePlugAVMME"
	case MRP:
		return "MRP"
	case MACSec:
		return "MACSec"
	case IEEE1588:
		return "IEEE1588"
	case IEEE802_1ag:
		return "IEEE802_1ag"
	case FCoE:
		return "FCoE"
	case FCoEInit:
		return "FCoEInit"
	case RoCE:
		return "RoCE"
	case CTP:
		return "CTP"
	case VeritasLLT:
		return "VeritasLLT"
	case IEEE1904_2:
		return "IEEE1904_2"
	default:
		return fmt.Sprintf("unknown type:0x%02x", e[0:2])
	}
}

type VLANTag uint32

const (
	NotTagged VLANTag = 0
	Tagged    VLANTag = 4
)

type PCP uint8

const (
	BK = PCP(0x01)
	BE = PCP(0x00)
	EE = PCP(0x02)
	CA = PCP(0x03)
	VI = PCP(0x04)
	VO = PCP(0x05)
	IC = PCP(0x06)
	NC = PCP(0x07)
)

func (pcp PCP) String() string {
	switch pcp {
	case BK:
		return "BK - Background"
	case BE:
		return "BE - Best Effort"
	case EE:
		return "EE - Excellent Effort"
	case CA:
		return "CA - Critical Applications"
	case VI:
		return "VI - Video"
	case VO:
		return "VO - Voice"
	case IC:
		return "IC - Internetwork Control"
	case NC:
		return "NC - Network Control"
	}
	return fmt.Sprintf("corrupt type: %v", uint8(pcp))
}

type Frame []byte

// NewFrame wraps an existing slice of bytes and provides some simple access functions to the MAC layer
func NewFrame(data []byte) Frame {
	return data
}

// NewFrameAndBuffer copies a slice into a new slice and returns a Frame
func NewFrameAndBuffer(data []byte) Frame {
	newData := make([]byte, len(data))
	copy(newData, data)
	return newData
}

func (f *Frame) String(length int) string {
	s := fmt.Sprintf("Len: %-5d, Dst/Src: %s/%s", length, f.MACDestination(), f.MACSource())
	mT := f.VLANTag()
	if mT == Tagged {
		s += fmt.Sprintf(" (0x%04x/0x%03x-%d)", f.VLANTPID(), f.VLANID(), f.VLANID())
	}
	s += fmt.Sprintf(", EthType: %s\n", f.MACEthertype(mT))
	return s
}

func (f *Frame) MACSource() net.HardwareAddr {
	return net.HardwareAddr((*f)[6:12])
}

func (f *Frame) MACDestination() net.HardwareAddr {
	return net.HardwareAddr((*f)[:6])
}

func (f *Frame) VLANTag() VLANTag {
	// TODO: Can ths be change to handle multiple tags.  Perhaps this should just return number of tags 0..max
	if ((*f)[12] == 0x81 && (*f)[13] == 0x00) || ((*f)[12] == 0x88 && (*f)[13] == 0xa8) {
		return Tagged
	}
	return NotTagged
}

func (f *Frame) VLANPCP() PCP {
	return PCP((*f)[14] & 0xE0)
}

func (f *Frame) VLANDEI() bool {
	return (*f)[14]&0x20 == 0x20
}

func (f *Frame) VLANID() uint16 {
	return binary.BigEndian.Uint16([]byte{(*f)[14] & 0x0f, (*f)[15]})
}

func (f *Frame) VLANTPID() uint16 {
	return binary.BigEndian.Uint16([]byte{(*f)[12], (*f)[13]})
}

func (f *Frame) MACEthertype(tag VLANTag) EthType {
	pos := 12 + tag
	return EthType{(*f)[pos], (*f)[pos+1]}
}

func (f *Frame) MACPayload(tag VLANTag) ([]byte, uint16) {
	off := 14 + uint16(tag)
	return (*f)[off:], off
}
