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
)

type Capability struct {
	Code   uint8
	Length uint8
}

type MPCapability struct {
	AFI      uint16
	Reserved uint8
	SAFI     uint16
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
