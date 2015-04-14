package bgp2go

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
	CAPABILITY_AS4_NUMBER       = 65
	CAPABILITY_ADD_PATH         = 69
	MAX_UINT8                   = 255
)

type Capability struct {
	Code   uint8
	Length uint8
}

/*
	This is struct where we store session's supported capabilities
	XXX: 4byte ASN: implementation must insure, that open msg either contains mappend 2byte asn in
	myasn field of open msg, or AS_TRANS(23456) if our asn > 65535
*/
type BGPCapabilities struct {
	SupportASN4 bool
	ASN4        uint32
	AddPath     uint8
}

//Multiprotocol Extension
type MPCapability struct {
	AFI  uint16
	_    uint8
	SAFI uint8
}

//ADDPath
type AddPathCapability struct {
	AFI  uint16
	SAFI uint16
	/* Send/Recv/both */
	Flags uint8
}

func isMPCapabilityEqual(cap1, cap2 MPCapability) bool {
	return (cap1.AFI == cap2.AFI) && (cap1.SAFI == cap2.SAFI)
}

func capInList(mpCap MPCapability, capList []MPCapability) bool {
	for _, val := range capList {
		if isMPCapabilityEqual(mpCap, val) {
			return true
		}
	}
	return false
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

func EncodeASN4Capability(asn4 uint32) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, &asn4)
	if err != nil {
		return nil, fmt.Errorf("cant encode asn4: %v\n", err)
	}
	capability, err := EncodeCapability(Capability{Code: CAPABILITY_AS4_NUMBER, Length: FOUR_OCTETS},
		buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("cant encode asn4 capabiltiy: %v\n", err)
	}
	return capability, nil
}

func DecodeASN4Capabiltiy(encAsn4 []byte) (uint32, error) {
	var asn4 uint32
	err := binary.Read(bytes.NewReader(encAsn4), binary.BigEndian, &asn4)
	if err != nil {
		return asn4, fmt.Errorf("cant decode asn4: %v\n", err)
	}
	return asn4, nil
}

/*
	TODO: right now i've implemented only capability anounce; no actual encoding for nlri w/ add path
	has been implemented yet
*/
func EncodeAddPathCapability(addPaths []AddPathCapability) ([]byte, error) {
	buf := new(bytes.Buffer)
	encodedAddPaths := make([]byte, 0)
	for _, addPath := range addPaths {
		err := binary.Write(buf, binary.BigEndian, &addPath)
		if err != nil {
			return nil, fmt.Errorf("cant encode AddPath: %v\n", err)
		}
		encodedAddPaths = append(encodedAddPaths, buf.Bytes()...)
	}
	//TODO: check that len of encodedAddPaths is less than 255
	capability, err := EncodeCapability(Capability{Code: CAPABILITY_ADD_PATH,
		Length: uint8(len(encodedAddPaths))},
		encodedAddPaths)
	if err != nil {
		return nil, fmt.Errorf("cant encode AddPath capabiltiy: %v\n", err)
	}
	return capability, nil

}

func DecodeAddPathCapability(capability []byte) ([]AddPathCapability, error) {
	addPathList := make([]AddPathCapability, 0)
	addPath := AddPathCapability{}
	if len(capability) < FIVE_OCTETS {
		return nil, fmt.Errorf("incorrect add path capability lenght (<5)\n")
	}
	for len(capability) > 0 {
		err := binary.Read(bytes.NewReader(capability), binary.BigEndian, &addPath)
		if err != nil {
			return nil, fmt.Errorf("cant decode add path capability: %v\n", err)
		}
		addPathList = append(addPathList, addPath)
		capability = capability[FIVE_OCTETS:]
	}

	return addPathList, nil
}
