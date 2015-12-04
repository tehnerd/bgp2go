package bgp2go

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	MP_AFI_IPV4     = 1
	MP_AFI_IPV6     = 2
	MP_AFI_VPLS     = 25
	MP_SAFI_UCAST   = 1
	MP_SAFI_MCAST   = 2
	MP_SAFI_LABELED = 4

	LABEL_SIZE_BITS = 24
	LABEL_BOS       = 1
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
		 we also have reserved byte, but we dont
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
		switch hdr.SAFI {
		case MP_SAFI_UCAST:
			nh, nlris, err := DecodeIPV4_MP_REACH_NLRI(bgpRoute.Flags, data, hdr)
			if err != nil {
				return err
			}
			bgpRoute.NEXT_HOPv4 = nh
			bgpRoute.Routes = append(bgpRoute.Routes, nlris...)
		case MP_SAFI_LABELED:
			bgpRoute.Flags.Labeled = true
			nh, nlris, err := DecodeIPV4_MP_REACH_NLRI(bgpRoute.Flags, data, hdr)
			if err != nil {
				return err
			}
			bgpRoute.NEXT_HOPv4 = nh
			bgpRoute.Routes = append(bgpRoute.Routes, nlris...)
		}
	case MP_AFI_IPV6:
		switch hdr.SAFI {
		case MP_SAFI_UCAST:
			nh, nlris, err := DecodeIPV6_MP_REACH_NLRI(data, hdr)
			if err != nil {
				return err
			}
			bgpRoute.NEXT_HOPv6 = nh
			bgpRoute.RoutesV6 = append(bgpRoute.RoutesV6, nlris...)
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
		switch hdr.SAFI {
		case MP_SAFI_UCAST:
			nlris, err := DecodeIPv4NLRI(bgpRoute.Flags, data)
			if err != nil {
				return err
			}
			bgpRoute.WithdrawRoutes = append(bgpRoute.WithdrawRoutes,
				nlris...)
		case MP_SAFI_LABELED:
			nlris, err := DecodeIPv4NLRI(bgpRoute.Flags, data)
			if err != nil {
				return err
			}
			bgpRoute.WithdrawRoutes = append(bgpRoute.WithdrawRoutes,
				nlris...)

		}
	case MP_AFI_IPV6:
		switch hdr.SAFI {
		case MP_SAFI_UCAST:
			nlris, err := DecodeIPv6NLRI(data)
			if err != nil {
				return err
			}
			bgpRoute.WithdrawRoutesV6 = append(bgpRoute.WithdrawRoutesV6,
				nlris...)
		case MP_SAFI_LABELED:
			nlris, err := DecodeIPv6NLRI(data)
			if err != nil {
				return err
			}
			bgpRoute.WithdrawRoutesV6 = append(bgpRoute.WithdrawRoutesV6,
				nlris...)

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
