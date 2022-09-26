package nettypes

type EthPacket interface {
	EthType() EthType
	Bytes() []byte
}
