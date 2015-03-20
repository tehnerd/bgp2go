package bgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

/*
	All details could be found in RFC5492
*/

const (
	CAPABILITIES_OPTIONAL_PARAM = 2
	CAPABILITY_MP_EXTENSION     = 1
	MAX_UINT8                   = 255
)

type Capability struct {
	Code   uint8
	Length uint8
}

//Multiprotocol Extension
type MPCapability struct {
	AFI      uint16
	Reserved uint8
	SAFI     uint8
}

func DecodeCapability(msg []byte) (Capability, []byte, error) {
	capability := Capability{}
	if len(msg) < TWO_OCTETS {
		return capability, nil, fmt.Errorf("error in capability length\n")
	}
	err := binary.Read(bytes.NewReader(msg), binary.BigEndian, &capability)
	if err != nil {
		return capability, nil, fmt.Errorf("error in capability decoding: %v\n", err)
	}
	if len(msg) < (TWO_OCTETS + int(capability.Length)) {
		return capability, nil, fmt.Errorf("error in capability decoding: capability len\n")
	}
	return capability, msg[TWO_OCTETS : TWO_OCTETS+capability.Length], nil
}

func EncodeCapability(capability Capability, data []byte) ([]byte, error) {
	if len(data) > MAX_UINT8 {
		return nil, fmt.Errorf("encoded capability is to big\n")
	}
	capability.Length = uint8(len(data))
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, &capability)
	if err != nil {
		return nil, fmt.Errorf("error during capability encoding: %v\n")
	}
	encodedCap := append(buf.Bytes(), data...)
	return encodedCap, nil
}

func DecodeMPCapability(msg []byte) (MPCapability, error) {
	mpCapabiltiy := MPCapability{}
	if len(msg) != FOUR_OCTETS {
		return mpCapabiltiy, fmt.Errorf("wrong len of mp capability")
	}
	err := binary.Read(bytes.NewReader(msg), binary.BigEndian, &mpCapabiltiy)
	if err != nil {
		return mpCapabiltiy, fmt.Errorf("error during mp capability decoding: %v\n", err)
	}
	return mpCapabiltiy, nil
}

func EncodeMPCapability(mpCap MPCapability) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, &mpCap)
	if err != nil {
		return nil, fmt.Errorf("error during mp capability encoding: %v\n", err)
	}
	return buf.Bytes(), nil
}
