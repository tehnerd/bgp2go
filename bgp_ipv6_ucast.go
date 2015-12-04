package bgp2go

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	IPV6_ADDRESS_LEN = 16
)

type IPv6Addr [4]uint32

func (ipv6 IPv6Addr) isEqual(oIpv6 IPv6Addr) bool {
	return (ipv6[0] == oIpv6[0] &&
		ipv6[1] == oIpv6[1] &&
		ipv6[2] == oIpv6[2] &&
		ipv6[3] == oIpv6[3])
}

type IPV6_NLRI struct {
	Length uint8
	Prefix IPv6Addr
}

//TODO(tehnerd): labeled ipv6 and add path for ipv6

//NH_LEN of 16 is hardcoded rightnow; TODO: support for linklocal
func EncodeIPv6NLRI(nlris []IPV6_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	encodedNlris := make([]byte, 0)
	for _, nlri := range nlris {
		err := binary.Write(buf, binary.BigEndian, &nlri.Length)
		if err != nil {
			return nil, fmt.Errorf("cant encode ipv6 nlri length: %v\n", err)
		}
		err = binary.Write(buf, binary.BigEndian, &nlri.Prefix)
		if err != nil {
			return nil, fmt.Errorf("cant encode ipv6 nlri length: %v\n", err)
		}
		encodingLen := (nlri.Length + 7) / 8
		encodedNlris = append(encodedNlris,
			buf.Bytes()[:ONE_OCTET+encodingLen]...)
		buf.Reset()
	}
	return encodedNlris, nil

}

func DecodeIPv6NLRI(data []byte) ([]IPV6_NLRI, error) {
	nlris := make([]IPV6_NLRI, 0)
	if len(data) < ONE_OCTET {
		return nlris, EndOfRib{}
	}
	for len(data) > 0 {
		ipv6nlri := IPV6_NLRI{}
		err := binary.Read(bytes.NewReader(data), binary.BigEndian, &ipv6nlri.Length)
		if err != nil {
			return nlris, fmt.Errorf("cant decode ipv6 nlri length: %v\n", err)
		}
		data = data[ONE_OCTET:]
		prefixPart := make([]byte, 0)
		prefixBytes := (ipv6nlri.Length + 7) / 8
		prefixPart = append(prefixPart, data[:prefixBytes]...)
		for len(prefixPart) < IPV6_ADDRESS_LEN {
			prefixPart = append(prefixPart, 0)
		}
		err = binary.Read(bytes.NewReader(prefixPart), binary.BigEndian, &ipv6nlri.Prefix)
		if err != nil {
			return nlris, fmt.Errorf("cant decode ipv6 nlri prefix: %v\n", err)
		}
		nlris = append(nlris, ipv6nlri)
		data = data[prefixBytes:]
	}
	return nlris, nil
}

func EncodeIPV6_MP_REACH_NLRI(nh IPv6Addr, nlris []IPV6_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	mpReachHdr := MP_REACH_NLRI_HDR{AFI: MP_AFI_IPV6, SAFI: MP_SAFI_UCAST,
		NHLength: IPV6_ADDRESS_LEN}
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
	encNLRI, err := EncodeIPv6NLRI(nlris)
	if err != nil {
		return nil, err
	}
	mp_reach := append(buf.Bytes(), encNLRI...)
	return mp_reach, nil
}

func DecodeIPV6_MP_REACH_NLRI(data []byte, mpHdr MP_REACH_NLRI_HDR) (IPv6Addr,
	[]IPV6_NLRI, error) {
	var nh IPv6Addr
	err := binary.Read(bytes.NewReader(data), binary.BigEndian, &nh)
	if err != nil {
		return nh, nil, err
	}
	/*
		TODO: check if len != IPV_ADDRESS_LEN (means that we have encoded link local
		as well
		one_octet -> reserved field
	*/
	data = data[mpHdr.NHLength+ONE_OCTET:]
	nlris, err := DecodeIPv6NLRI(data)
	if err != nil {
		return nh, nil, fmt.Errorf("cant decode ipv6 nlri: %v\n", err)
	}
	return nh, nlris, nil
}

func EncodeIPV6_MP_UNREACH_NLRI(nlris []IPV6_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	mpUnreachHdr := MP_UNREACH_NLRI_HDR{AFI: MP_AFI_IPV6, SAFI: MP_SAFI_UCAST}
	err := binary.Write(buf, binary.BigEndian, &mpUnreachHdr)
	if err != nil {
		return nil, err
	}
	encNLRI, err := EncodeIPv6NLRI(nlris)
	if err != nil {
		return nil, err
	}
	mp_unreach := append(buf.Bytes(), encNLRI...)
	return mp_unreach, nil
}
