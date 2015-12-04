package bgp2go

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	/* Attributes */

	BAF_OPTIONAL   = 0x80
	BAF_TRANSITIVE = 0x40
	BAF_PARTIAL    = 0x20
	BAF_EXT_LEN    = 0x10

	BA_ORIGIN          = 0x01
	BA_AS_PATH         = 0x02
	BA_NEXT_HOP        = 0x03
	BA_MULTI_EXIT_DISC = 0x04
	BA_LOCAL_PREF      = 0x05
	BA_ATOMIC_AGGR     = 0x06
	BA_AGGREGATOR      = 0x07
	BA_COMMUNITY       = 0x08
	BA_ORIGINATOR_ID   = 0x09
	BA_CLUSTER_LIST    = 0x0a

	BA_DPA             = 0x0b
	BA_ADVERTISER      = 0x0c
	BA_RCID_PATH       = 0x0d
	BA_MP_REACH_NLRI   = 0x0e
	BA_MP_UNREACH_NLRI = 0x0f
	BA_EXT_COMMUNITY   = 0x10
	BA_AS4_PATH        = 0x11
	BA_AS4_AGGREGATOR  = 0x12

	ORIGIN_IGP        = 0
	ORIGIN_EGP        = 1
	ORIGIN_INCOMPLETE = 2

	/* Well-known communities */

	BGP_COMM_NO_EXPORT           = 0xffffff01 /* Don't export outside local AS / confed. */
	BGP_COMM_NO_ADVERTISE        = 0xffffff02 /* Don't export at all */
	BGP_COMM_NO_EXPORT_SUBCONFED = 0xffffff03 /* NO_EXPORT even in local confederation */

	AS_SET = 1
	AS_SEQ = 2
)

type PathAttr struct {
	AttrFlags      uint8
	AttrTypeCode   uint8
	AttrLength     uint16
	ExtendedLength bool
	Data           []byte
}

func EncodePathAttr(pathAttr *PathAttr, data []byte) ([]byte, error) {

	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.BigEndian, &pathAttr.AttrFlags)
	if err != nil {
		return nil, fmt.Errorf("cant encode path attr flags: %v\n", err)
	}

	err = binary.Write(buf, binary.BigEndian, &pathAttr.AttrTypeCode)
	if err != nil {
		return nil, fmt.Errorf("cant encode path attr type code: %v\n", err)
	}

	if pathAttr.ExtendedLength {
		attrLen := uint16(len(data))
		err = binary.Write(buf, binary.BigEndian, &attrLen)
		if err != nil {
			return nil, fmt.Errorf("cant encode path attr ext length: %v\n", err)
		}
	} else {
		attrLen := uint8(len(data))
		err = binary.Write(buf, binary.BigEndian, &attrLen)
		if err != nil {
			return nil, fmt.Errorf("cant encode path attr ext length: %v\n", err)
		}

	}
	data = append(buf.Bytes(), data...)
	return data, nil
}

func EncodeBGPRouteAttrs(bgpRoute *BGPRoute) ([]byte, error) {
	encodedAttrs := make([]byte, 0)
	pathAttr := PathAttr{}
	data, err := EncodeOriginAttr(&bgpRoute.ORIGIN, &pathAttr)
	if err != nil {
		return nil, err
	}
	encodedAttrs = append(encodedAttrs, data...)

	//For MP-BGP next_hop is not a mandatory attribute; coz we have another one in mp-nlri
	if bgpRoute.NEXT_HOP != nil {
		data, err = EncodeNextHopAttr(bgpRoute.NEXT_HOP, &pathAttr)
		if err != nil {
			return nil, err
		}

		encodedAttrs = append(encodedAttrs, data...)
	}
	//TODO: implement "withdraw" flag; so we wont check this len for each of supported mp-afi
	if len(bgpRoute.WithdrawRoutesV6) == 0 {
		data, err = EncodeASPathAttr(bgpRoute.AS_PATH, &pathAttr, bgpRoute.ASN4)
		if err != nil {
			return nil, err
		}
		encodedAttrs = append(encodedAttrs, data...)
	}

	if len(bgpRoute.WithdrawRoutesV6) == 0 {
		if bgpRoute.MULTI_EXIT_DISC != 0 {
			data, err = EncodeMEDAttr(&bgpRoute.MULTI_EXIT_DISC, &pathAttr)
			if err != nil {
				return nil, err
			}
			encodedAttrs = append(encodedAttrs, data...)
		}
	}

	if bgpRoute.LOCAL_PREF != 0 {
		data, err = EncodeLPAttr(&bgpRoute.LOCAL_PREF, &pathAttr)
		if err != nil {
			return nil, err
		}
		encodedAttrs = append(encodedAttrs, data...)
	}
	if bgpRoute.ATOMIC_AGGR {
		data, err = EncodeAAGRAttr(&pathAttr)
		if err != nil {
			return nil, err
		}
		encodedAttrs = append(encodedAttrs, data...)

	}
	if len(bgpRoute.RoutesV6) != 0 {
		data, err = EncodeV6MPRNLRI(bgpRoute.NEXT_HOPv6,
			bgpRoute.RoutesV6, &pathAttr)
		if err != nil {
			return nil, err
		}
		encodedAttrs = append(encodedAttrs, data...)
	}
	if len(bgpRoute.WithdrawRoutesV6) != 0 {
		data, err = EncodeV6MPUNRNLRI(bgpRoute.WithdrawRoutesV6,
			&pathAttr)
		if err != nil {
			return nil, err
		}
		encodedAttrs = append(encodedAttrs, data...)
	}
	if bgpRoute.MPINET {
		if len(bgpRoute.Routes) != 0 {
			data, err = EncodeV4MPRNLRI(bgpRoute.NEXT_HOPv4,
				bgpRoute.Flags, bgpRoute.Routes, &pathAttr)
			if err != nil {
				return nil, err
			}
			encodedAttrs = append(encodedAttrs, data...)
		}
		if len(bgpRoute.WithdrawRoutes) != 0 {
			data, err = EncodeV4MPUNRNLRI(bgpRoute.Flags,
				bgpRoute.WithdrawRoutes, &pathAttr)
			if err != nil {
				return nil, err
			}
			encodedAttrs = append(encodedAttrs, data...)
		}
	}

	if len(bgpRoute.Community) != 0 {
		for _, community := range bgpRoute.Community {
			data, err := EncodeBGPCommunity(community, &pathAttr)
			if err != nil {
				return nil, err
			}
			encodedAttrs = append(encodedAttrs, data...)
		}
	}

	return encodedAttrs, nil
}

func EncodeMEDAttr(med *uint32, pathAttr *PathAttr) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, med)
	if err != nil {
		return nil, fmt.Errorf("error during MULTI_EXIT_DISC encoding: %v\n", err)
	}
	pathAttr.AttrFlags = BAF_OPTIONAL
	pathAttr.AttrTypeCode = BA_MULTI_EXIT_DISC
	/*
	   this is generic copy-paste code; uint32 would never exceed 255bytes in len.
	   mb will remove it later
	*/
	encData := buf.Bytes()
	if len(encData) > 255 {
		pathAttr.ExtendedLength = true
		pathAttr.AttrFlags |= BAF_EXT_LEN
	} else {
		pathAttr.ExtendedLength = false
	}
	encodedAttr, err := EncodePathAttr(pathAttr, encData)
	if err != nil {
		return nil, fmt.Errorf("error during ORIGIN attr encoding: %v\n", err)
	}
	return encodedAttr, nil
}

func EncodeLPAttr(lp *uint32, pathAttr *PathAttr) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, lp)
	if err != nil {
		return nil, fmt.Errorf("error during MULTI_EXIT_DISC encoding: %v\n", err)
	}
	pathAttr.AttrFlags = BAF_TRANSITIVE
	pathAttr.AttrTypeCode = BA_LOCAL_PREF
	encData := buf.Bytes()
	if len(encData) > 255 {
		pathAttr.ExtendedLength = true
		pathAttr.AttrFlags |= BAF_EXT_LEN
	} else {
		pathAttr.ExtendedLength = false
	}
	encodedAttr, err := EncodePathAttr(pathAttr, encData)
	if err != nil {
		return nil, fmt.Errorf("error during LOCAL_PREF attr encoding: %v\n", err)
	}
	return encodedAttr, nil
}

func EncodeAAGRAttr(pathAttr *PathAttr) ([]byte, error) {
	pathAttr.AttrFlags = BAF_TRANSITIVE
	pathAttr.AttrTypeCode = BA_ATOMIC_AGGR
	pathAttr.ExtendedLength = false
	zeroLen := make([]byte, 0)
	encodedAttr, err := EncodePathAttr(pathAttr, zeroLen)
	if err != nil {
		return nil, fmt.Errorf("error during ATOMIC_AGGR attr encoding: %v\n", err)
	}
	return encodedAttr, nil
}

func EncodeOriginAttr(origin *uint8, pathAttr *PathAttr) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, origin)
	if err != nil {
		return nil, fmt.Errorf("error during ORIGIN encoding: %v\n", err)
	}
	pathAttr.AttrFlags = BAF_TRANSITIVE
	pathAttr.AttrTypeCode = BA_ORIGIN
	encData := buf.Bytes()
	if len(encData) > 255 {
		pathAttr.ExtendedLength = true
		pathAttr.AttrFlags |= BAF_EXT_LEN
	} else {
		pathAttr.ExtendedLength = false
	}
	encodedAttr, err := EncodePathAttr(pathAttr, encData)
	if err != nil {
		return nil, fmt.Errorf("error during ORIGIN attr encoding: %v\n", err)
	}
	return encodedAttr, nil
}

func EncodeNextHopAttr(nh []byte, pathAttr *PathAttr) ([]byte, error) {
	pathAttr.AttrFlags = BAF_TRANSITIVE
	pathAttr.AttrTypeCode = BA_NEXT_HOP
	encData := nh
	if len(encData) > 255 {
		pathAttr.ExtendedLength = true
		pathAttr.AttrFlags |= BAF_EXT_LEN
	} else {
		pathAttr.ExtendedLength = false
	}
	encodedAttr, err := EncodePathAttr(pathAttr, encData)
	if err != nil {
		return nil, fmt.Errorf("error during ORIGIN attr encoding: %v\n", err)
	}
	return encodedAttr, nil
}

func EncodeV6MPRNLRI(nh IPv6Addr, nlris []IPV6_NLRI, pathAttr *PathAttr) ([]byte, error) {
	pathAttr.AttrFlags = BAF_OPTIONAL
	pathAttr.AttrTypeCode = BA_MP_REACH_NLRI
	encData, err := EncodeIPV6_MP_REACH_NLRI(nh, nlris)
	if err != nil {
		return nil, fmt.Errorf("cant encode ipv6 mp reach nlri: %v\n", err)
	}
	pathAttr.ExtendedLength = true
	pathAttr.AttrFlags |= BAF_EXT_LEN
	encodedAttr, err := EncodePathAttr(pathAttr, encData)
	if err != nil {
		return nil, fmt.Errorf("error during MP_REACH_NLRI attr encoding: %v\n", err)
	}
	return encodedAttr, nil
}

func EncodeV4MPRNLRI(nh uint32, flags RouteFlags, nlris []IPV4_NLRI,
	pathAttr *PathAttr) ([]byte, error) {
	pathAttr.AttrFlags = BAF_OPTIONAL
	pathAttr.AttrTypeCode = BA_MP_REACH_NLRI
	encData, err := EncodeIPV4_MP_REACH_NLRI(nh, flags, nlris)
	if err != nil {
		return nil, fmt.Errorf("cant encode ipv4 mp reach nlri: %v\n", err)
	}
	pathAttr.ExtendedLength = true
	pathAttr.AttrFlags |= BAF_EXT_LEN
	encodedAttr, err := EncodePathAttr(pathAttr, encData)
	if err != nil {
		return nil, fmt.Errorf("error during MP_REACH_NLRI attr encoding: %v\n", err)
	}
	return encodedAttr, nil
}

func EncodeV6MPUNRNLRI(nlris []IPV6_NLRI, pathAttr *PathAttr) ([]byte, error) {
	pathAttr.AttrFlags = BAF_OPTIONAL
	pathAttr.AttrTypeCode = BA_MP_UNREACH_NLRI
	encData, err := EncodeIPV6_MP_UNREACH_NLRI(nlris)
	if err != nil {
		return nil, fmt.Errorf("cant encode ipv6 mp unreach nlri: %v\n", err)
	}
	pathAttr.ExtendedLength = true
	pathAttr.AttrFlags |= BAF_EXT_LEN
	encodedAttr, err := EncodePathAttr(pathAttr, encData)
	if err != nil {
		return nil, fmt.Errorf("error during MP_UNREACH_NLRI attr encoding: %v\n", err)
	}
	return encodedAttr, nil
}

func EncodeV4MPUNRNLRI(flags RouteFlags, nlris []IPV4_NLRI,
	pathAttr *PathAttr) ([]byte, error) {
	pathAttr.AttrFlags = BAF_OPTIONAL
	pathAttr.AttrTypeCode = BA_MP_UNREACH_NLRI
	encData, err := EncodeIPV4_MP_UNREACH_NLRI(flags, nlris)
	if err != nil {
		return nil, fmt.Errorf("cant encode ipv4 mp unreach nlri: %v\n", err)
	}
	pathAttr.ExtendedLength = true
	pathAttr.AttrFlags |= BAF_EXT_LEN
	encodedAttr, err := EncodePathAttr(pathAttr, encData)
	if err != nil {
		return nil, fmt.Errorf("error during MP_UNREACH_NLRI attr encoding: %v\n", err)
	}
	return encodedAttr, nil
}

func EncodeBGPCommunity(community uint32, pathAttr *PathAttr) ([]byte, error) {
	pathAttr.AttrFlags = BAF_TRANSITIVE | BAF_OPTIONAL
	pathAttr.AttrTypeCode = BA_COMMUNITY
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, &community)
	if err != nil {
		return nil, fmt.Errorf("error during community encoding: %v\n", err)
	}
	pathAttr.ExtendedLength = false
	encodedAttr, err := EncodePathAttr(pathAttr, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error during AS_PATH attr encoding: %v\n", err)
	}
	return encodedAttr, nil
}

/*
TODO: lots of things must be implemented.(for example as_path can has more than one
path_segment. also not sure will it work with non zero as_path (gonna test/fix it later,
right now i need only update msg with empty as_path)
*/
func EncodeASPathAttr(pathSegment []PathSegment, pathAttr *PathAttr, asn4 bool) ([]byte, error) {
	pathAttr.AttrFlags = BAF_TRANSITIVE
	pathAttr.AttrTypeCode = BA_AS_PATH
	var as2 uint16
	encData := make([]byte, 0)
	for _, segment := range pathSegment {
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.BigEndian, &segment.PSType)
		if err != nil {
			return nil, fmt.Errorf("error during AS_PATH ps_type attr encoding: %v\n", err)
		}
		err = binary.Write(buf, binary.BigEndian, &segment.PSLength)
		if err != nil {
			return nil, fmt.Errorf("error during AS_PATH ps_length attr encoding: %v\n", err)
		}
		for _, asn := range segment.PSValue {
			if !asn4 {
				as2 = uint16(asn)
				err = binary.Write(buf, binary.BigEndian, &as2)
				if err != nil {
					return nil, fmt.Errorf("error during AS_PATH asn attr encoding: %v\n", err)
				}
			} else {
				err = binary.Write(buf, binary.BigEndian, &asn)
				if err != nil {
					return nil, fmt.Errorf("error during AS_PATH asn attr encoding: %v\n", err)
				}
			}
		}
		encData = append(encData, buf.Bytes()...)
	}
	if len(encData) > 255 {
		pathAttr.ExtendedLength = true
	} else {
		pathAttr.ExtendedLength = false
	}
	encodedAttr, err := EncodePathAttr(pathAttr, encData)
	if err != nil {
		return nil, fmt.Errorf("error during AS_PATH attr encoding: %v\n", err)
	}
	return encodedAttr, nil
}

func DecodePathAttr(msg []byte, pathAttr *PathAttr) error {
	reader := bytes.NewReader(msg)
	pathAttr.ExtendedLength = false
	err := binary.Read(reader, binary.BigEndian, &(pathAttr.AttrFlags))
	if err != nil {
		return errors.New("cant decode update msg")
	}
	err = binary.Read(reader, binary.BigEndian, &(pathAttr.AttrTypeCode))
	if err != nil {
		return errors.New("cant decode update msg")
	}
	if pathAttr.AttrFlags&BAF_EXT_LEN != 0 {
		err = binary.Read(reader, binary.BigEndian, &(pathAttr.AttrLength))
		if err != nil {
			return errors.New("cant decode update msg")
		}
		pathAttr.ExtendedLength = true
		pathAttr.Data = msg[FOUR_OCTET_SHIFT : FOUR_OCTET_SHIFT+int(pathAttr.AttrLength)]
	} else {
		tmpLength := uint8(0)
		err = binary.Read(reader, binary.BigEndian, &(tmpLength))
		if err != nil {
			return errors.New("cant decode update msg")
		}
		pathAttr.AttrLength = uint16(tmpLength)
		pathAttr.Data = msg[THREE_OCTET_SHIFT : THREE_OCTET_SHIFT+int(pathAttr.AttrLength)]
	}
	return nil
}
