package bgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	IPV6_NEXTHOP_LEN = 16
)

type IPv6Addr [4]uint32

type IPV6_NLRI struct {
	Length uint8
	Prefix IPv6Addr
}

//NH_LEN of 16 is hardcoded rightnow; TODO: support for linklocal
func EncodeIPv6NLRI(nlri IPV6_NLRI) ([]byte, error) {
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

func EncodeIPV6_MP_REACH_NLRI(nh IPv6Addr, nlri IPV6_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	mpReachHdr := MP_REACH_NLRI_HDR{AFI: MP_AFI_IPV6, SAFI: MP_SAFI_UCAST,
		NHLength: IPV6_NEXTHOP_LEN}
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
	encNLRI, err := EncodeIPv6NLRI(nlri)
	if err != nil {
		return nil, err
	}
	mp_reach := append(buf.Bytes(), encNLRI...)
	return mp_reach, nil
}
