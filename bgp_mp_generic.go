package bgp2go

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	MP_AFI_IPV4   = 1
	MP_AFI_IPV6   = 2
	MP_AFI_VPLS   = 25
	MP_SAFI_UCAST = 1
	MP_SAFI_MCAST = 2
)

/*
 Detail info could be found in RFC4760
*/

type MP_REACH_NLRI_HDR struct {
	AFI      uint16
	SAFI     uint8
	NHLength uint8
	//NEXT_HOP variable length
	/*
		 we also has reserved byte, but we dont
		add it to this struct coz it will be harder for
		us to decode it (we have nh of variable length between
		afi/safi/nhlen and reserved)
	*/
	//RESERVED uint8 (ONE_OCTET)
	//MP_NRLI variable length
}

type MP_UNREACH_NLRI_HDR struct {
	AFI  uint16
	SAFI uint8
	//WithdrawRoutes
}

func DecodeMP_REACH_NLRI_HDR(data []byte) (MP_REACH_NLRI_HDR, error) {
	var hdr MP_REACH_NLRI_HDR
	if len(data) < FOUR_OCTETS {
		return hdr, fmt.Errorf("error in length of mp_reach_nlri hdr\n")
	}
	err := binary.Read(bytes.NewReader(data), binary.BigEndian, &hdr)
	if err != nil {
		return hdr, fmt.Errorf("cant decode mp_reach_nlri hdr: %v\n", err)
	}
	return hdr, nil
}

func DecodeMP_REACH_NLRI(data []byte, bgpRoute *BGPRoute) error {
	hdr, err := DecodeMP_REACH_NLRI_HDR(data)
	if err != nil {
		return err
	}
	//hdr size
	data = data[FOUR_OCTET_SHIFT:]
	switch hdr.AFI {
	case MP_AFI_IPV4:
	case MP_AFI_IPV6:
		switch hdr.SAFI {
		case MP_SAFI_UCAST:
			nh, nlri, err := DecodeIPV6_MP_REACH_NLRI(data, hdr)
			if err != nil {
				return err
			}
			bgpRoute.NEXT_HOPv6 = nh
			bgpRoute.RoutesV6 = append(bgpRoute.RoutesV6, nlri)
		}
	}
	return nil
}

func DecodeMP_UNREACH_NLRI(data []byte, bgpRoute *BGPRoute) error {
	hdr, err := DecodeMP_UNREACH_NLRI_HDR(data)
	if err != nil {
		return err
	}
	//unreach hdr size
	data = data[THREE_OCTET_SHIFT:]
	switch hdr.AFI {
	case MP_AFI_IPV4:
	case MP_AFI_IPV6:
		switch hdr.SAFI {
		case MP_SAFI_UCAST:
			nlri, err := DecodeIPv6NLRI(data)
			if err != nil {
				return err
			}
			bgpRoute.WithdrawRoutesV6 = append(bgpRoute.WithdrawRoutesV6, nlri)
		}
	}
	return nil
}

func DecodeMP_UNREACH_NLRI_HDR(data []byte) (MP_UNREACH_NLRI_HDR, error) {
	var hdr MP_UNREACH_NLRI_HDR
	if len(data) < THREE_OCTETS {
		return hdr, fmt.Errorf("error in length of mp_unreach_nlri hdr\n")
	}
	err := binary.Read(bytes.NewReader(data), binary.BigEndian, &hdr)
	if err != nil {
		return hdr, fmt.Errorf("cant decode mp_unreach_nlri hdr: %v\n", err)
	}
	return hdr, nil
}
