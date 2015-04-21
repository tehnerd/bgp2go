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
func EncodeIPv4NLRI(flags RouteFlags, nlri IPV4_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, &nlri.Length)
	if err != nil {
		return nil, fmt.Errorf("cant encode ipv4 nlri's length: %v\n", err)
	}
	additionalData := uint8(0)
	if flags.Labeled {
		label := ((nlri.Label << 4) | 1)
		additionalData += 3
		lBuffer := new(bytes.Buffer)
		err = binary.Write(lBuffer, binary.BigEndian, &label)
		if err != nil {
			return nil, fmt.Errorf("cant encode ipv4 nlri's label: %v\n", err)
		}
		n, _ := buf.Write(lBuffer.Bytes()[1:])
		if n != 3 {
			return nil, fmt.Errorf("cant encode ipv4 nlri's label: %v\n", err)
		}
	}
	err = binary.Write(buf, binary.BigEndian, &nlri.Prefix)
	if err != nil {
		return nil, fmt.Errorf("cant encode ipv6 nlri length: %v\n", err)
	}
	encodingLen := (nlri.Length + 7) / 8
	return buf.Bytes()[:ONE_OCTET+encodingLen+additionalData], nil
}

//this is routine for decoding of ipv4 route as mp_reach/unreach nlri
func DecodeIPv4NLRI(flags RouteFlags, data []byte) (IPV4_NLRI, error) {
	nlri := IPV4_NLRI{}
	if len(data) < ONE_OCTET {
		return nlri, fmt.Errorf("error in ipv4 nlri length(=0)\n")
	}
	if flags.WithPathId {
		err := binary.Read(bytes.NewReader(data), binary.BigEndian, &nlri.PathID)
		if err != nil {
			return nlri, fmt.Errorf("cant decode nlri's pathId: %v\n", err)
		}
		data = data[FOUR_OCTETS:]
	}
	err := binary.Read(bytes.NewReader(data), binary.BigEndian, &nlri.Length)
	if err != nil {
		return nlri, fmt.Errorf("cant decode ipv4 nlri length: %v\n", err)
	}
	data = data[ONE_OCTET:]
	if flags.Labeled {
		encLabel := make([]byte, 1)
		encLabel = append(encLabel, data[:THREE_OCTETS]...)
		fmt.Println(data[:THREE_OCTETS])
		fmt.Println(encLabel)
		label := uint32(0)
		err := binary.Read(bytes.NewReader(encLabel), binary.BigEndian, &label)
		if err != nil {
			return nlri, fmt.Errorf("cant decode nlri's label: %v\n", err)
		}
		nlri.Label = (label >> 4)
		data = data[THREE_OCTETS:]
	}
	prefixPart := make([]byte, 0)
	prefixBytes := (nlri.Length + 7) / 8
	prefixPart = append(prefixPart, data[:prefixBytes]...)
	for len(prefixPart) < IPV4_ADDRESS_LEN {
		prefixPart = append(prefixPart, 0)
	}
	err = binary.Read(bytes.NewReader(prefixPart), binary.BigEndian, &nlri.Prefix)
	if err != nil {
		return nlri, fmt.Errorf("cant decode ipv4 nlri prefix: %v\n", err)
	}
	return nlri, nil
}

//TODO(tehnerd): accept mp_reach_nlri_hdr as input val for func
func EncodeIPV4_MP_REACH_NLRI(nh uint32, flags RouteFlags, nlri IPV4_NLRI) ([]byte, error) {
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
	if flags.WithPathId {
		err = binary.Write(buf, binary.BigEndian, &nlri.PathID)
		if err != nil {
			return nil, err
		}
	}
	encNLRI, err := EncodeIPv4NLRI(flags, nlri)
	if err != nil {
		return nil, err
	}
	mp_reach := append(buf.Bytes(), encNLRI...)
	return mp_reach, nil
}

func EncodeLabeledIPV4_MP_REACH_NLRI(nh uint32,
	flags RouteFlags, nlri IPV4_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	mpReachHdr := MP_REACH_NLRI_HDR{AFI: MP_AFI_IPV4, SAFI: MP_SAFI_LABELED,
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
	if flags.WithPathId {
		err = binary.Write(buf, binary.BigEndian, &nlri.PathID)
		if err != nil {
			return nil, err
		}
	}
	encNLRI, err := EncodeIPv4NLRI(flags, nlri)
	if err != nil {
		return nil, err
	}
	mp_reach := append(buf.Bytes(), encNLRI...)
	return mp_reach, nil
}

func DecodeIPV4_MP_REACH_NLRI(flags RouteFlags,
	data []byte, mpHdr MP_REACH_NLRI_HDR) (uint32, IPV4_NLRI, error) {
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
	nlri, err = DecodeIPv4NLRI(flags, data)
	if err != nil {
		return nh, nlri, fmt.Errorf("cant decode ipv4 nlri: %v\n", err)
	}
	return nh, nlri, nil
}

func EncodeIPV4_MP_UNREACH_NLRI(flags RouteFlags, nlri IPV4_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	mpUnreachHdr := MP_UNREACH_NLRI_HDR{AFI: MP_AFI_IPV4, SAFI: MP_SAFI_UCAST}
	err := binary.Write(buf, binary.BigEndian, &mpUnreachHdr)
	if err != nil {
		return nil, err
	}
	encNLRI, err := EncodeIPv4NLRI(flags, nlri)
	if err != nil {
		return nil, err
	}
	mp_unreach := append(buf.Bytes(), encNLRI...)
	return mp_unreach, nil
}

func EncodeLabeledIPV4_MP_UNREACH_NLRI(flags RouteFlags, nlri IPV4_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	mpUnreachHdr := MP_UNREACH_NLRI_HDR{AFI: MP_AFI_IPV4, SAFI: MP_SAFI_LABELED}
	err := binary.Write(buf, binary.BigEndian, &mpUnreachHdr)
	if err != nil {
		return nil, err
	}
	encNLRI, err := EncodeIPv4NLRI(flags, nlri)
	if err != nil {
		return nil, err
	}
	mp_unreach := append(buf.Bytes(), encNLRI...)
	return mp_unreach, nil
}
