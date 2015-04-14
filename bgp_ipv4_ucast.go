package bgp2go

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	IPV4_ADDRESS_LEN = 4
)

//this is routine for  encoding of ipv4 route as mp_reach/unreach nlri (part of)
func EncodeIPv4NLRI(nlri IPV4_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, &nlri.Length)
	if err != nil {
		return nil, fmt.Errorf("cant encode ipv6 nlri length: %v\n", err)
	}
	err = binary.Write(buf, binary.BigEndian, &nlri.Prefix)
	if err != nil {
		return nil, fmt.Errorf("cant encode ipv6 nlri length: %v\n", err)
	}
	encodingLen := (nlri.Length + 7) / 8
	return buf.Bytes()[:ONE_OCTET+encodingLen], nil
}

//this is routine for decoding of ipv4 route as mp_reach/unreach nlri
func DecodeIPv4NLRI(data []byte) (IPV4_NLRI, error) {
	nlri := IPV4_NLRI{}
	if len(data) < ONE_OCTET {
		return nlri, fmt.Errorf("error in ipv4 nlri length(=0)\n")
	}
	err := binary.Read(bytes.NewReader(data), binary.BigEndian, &nlri.Length)
	if err != nil {
		return nlri, fmt.Errorf("cant decode ipv4 nlri length: %v\n", err)
	}
	prefixPart := make([]byte, 0)
	prefixBytes := (nlri.Length + 7) / 8
	prefixPart = append(prefixPart, data[ONE_OCTET:ONE_OCTET+prefixBytes]...)
	for len(prefixPart) < IPV4_ADDRESS_LEN {
		prefixPart = append(prefixPart, 0)
	}
	err = binary.Read(bytes.NewReader(prefixPart), binary.BigEndian, &nlri.Prefix)
	if err != nil {
		return nlri, fmt.Errorf("cant decode ipv4 nlri prefix: %v\n", err)
	}
	return nlri, nil
}

func EncodeIPV4_MP_REACH_NLRI(nh uint32, nlri IPV4_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	mpReachHdr := MP_REACH_NLRI_HDR{AFI: MP_AFI_IPV4, SAFI: MP_SAFI_UCAST,
		NHLength: IPV4_ADDRESS_LEN}
	err := binary.Write(buf, binary.BigEndian, &mpReachHdr)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, &nh)
	if err != nil {
		return nil, err
	}
	reserved := uint8(0)
	err = binary.Write(buf, binary.BigEndian, &reserved)
	if err != nil {
		return nil, err
	}
	encNLRI, err := EncodeIPv4NLRI(nlri)
	if err != nil {
		return nil, err
	}
	mp_reach := append(buf.Bytes(), encNLRI...)
	return mp_reach, nil
}

func DecodeIPV4_MP_REACH_NLRI(data []byte, mpHdr MP_REACH_NLRI_HDR) (uint32, IPV4_NLRI, error) {
	var nh uint32
	var nlri IPV4_NLRI
	err := binary.Read(bytes.NewReader(data), binary.BigEndian, &nh)
	if err != nil {
		return nh, nlri, fmt.Errorf("cant decode ipv4 nlri's nh: %v\n", err)
	}
	/*
		one_octet -> reserved field
	*/
	data = data[mpHdr.NHLength+ONE_OCTET:]
	nlri, err = DecodeIPv4NLRI(data)
	if err != nil {
		return nh, nlri, fmt.Errorf("cant decode ipv4 nlri: %v\n", err)
	}
	return nh, nlri, nil
}

func EncodeIPV4_MP_UNREACH_NLRI(nlri IPV4_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	mpUnreachHdr := MP_UNREACH_NLRI_HDR{AFI: MP_AFI_IPV4, SAFI: MP_SAFI_UCAST}
	err := binary.Write(buf, binary.BigEndian, &mpUnreachHdr)
	if err != nil {
		return nil, err
	}
	encNLRI, err := EncodeIPv4NLRI(nlri)
	if err != nil {
		return nil, err
	}
	mp_unreach := append(buf.Bytes(), encNLRI...)
	return mp_unreach, nil
}
