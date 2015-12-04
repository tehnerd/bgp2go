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
func EncodeIPv4NLRI(flags RouteFlags, nlris []IPV4_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	encodedNlris := make([]byte, 0)
	for _, nlri := range nlris {
		encodingLen := (nlri.Length + 7) / 8
		if flags.Labeled {
			//Size of the label in octets
			nlri.Length += LABEL_SIZE_BITS
		}
		err := binary.Write(buf, binary.BigEndian, &nlri.Length)
		if err != nil {
			return nil, fmt.Errorf("cant encode ipv4 nlri's length: %v\n", err)
		}
		var additionalData uint8
		if flags.Labeled {
			//mpls label: <20 bits label><3 bits TC(aka exp)><1 bit bos>
			label := uint32(((nlri.Label << 4) | LABEL_BOS))
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
		encodedNlris = append(encodedNlris,
			buf.Bytes()[:ONE_OCTET+encodingLen+additionalData]...)
		buf.Reset()
	}
	return encodedNlris, nil
}

//this is routine for decoding of ipv4 route as mp_reach/unreach nlri
func DecodeIPv4NLRI(flags RouteFlags, data []byte) ([]IPV4_NLRI, error) {
	nlris := make([]IPV4_NLRI, 0)
	var pathID uint32
	if len(data) < ONE_OCTET {
		return nlris, EndOfRib{}
	}
	if flags.WithPathId {
		err := binary.Read(bytes.NewReader(data), binary.BigEndian, &pathID)
		if err != nil {
			return nlris, fmt.Errorf("cant decode nlri's pathId: %v\n", err)
		}
		data = data[FOUR_OCTETS:]
	}
	for len(data) > 0 {
		nlri := IPV4_NLRI{}
		nlri.PathID = pathID
		err := binary.Read(bytes.NewReader(data), binary.BigEndian, &nlri.Length)
		if err != nil {
			return nlris, fmt.Errorf("cant decode ipv4 nlri length: %v\n", err)
		}
		data = data[ONE_OCTET:]
		if flags.Labeled {
			encLabel := make([]byte, 1)
			encLabel = append(encLabel, data[:THREE_OCTETS]...)
			label := uint32(0)
			err := binary.Read(bytes.NewReader(encLabel), binary.BigEndian, &label)
			if err != nil {
				return nlris, fmt.Errorf("cant decode nlri's label: %v\n", err)
			}
			nlri.Label = (label >> 4)
			nlri.Length -= LABEL_SIZE_BITS
			//FIXME(tehnerd): check data size; mailformed packets could result w/ outofbound
			if len(data) < 3 {
				panic(len(data))
			}
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
			return nlris, fmt.Errorf("cant decode ipv4 nlri prefix: %v\n", err)
		}
		nlris = append(nlris, nlri)
		data = data[prefixBytes:]
	}
	return nlris, nil
}

//TODO(tehnerd): accept mp_reach_nlri_hdr as input val for func
func EncodeIPV4_MP_REACH_NLRI(nh uint32, flags RouteFlags, nlris []IPV4_NLRI) ([]byte, error) {
	if len(nlris) < 1 {
		return nil, fmt.Errorf("zero length NLRIs slice\n")
	}
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
		/*
			we can group nlris into the same slice only if all of em has the same
			bgp's path attrs and same pathID, so it's safe to only look at first nlri for
			path's id value
		*/
		err = binary.Write(buf, binary.BigEndian, &nlris[0].PathID)
		if err != nil {
			return nil, err
		}
	}
	encNLRI, err := EncodeIPv4NLRI(flags, nlris)
	if err != nil {
		return nil, err
	}
	mp_reach := append(buf.Bytes(), encNLRI...)
	return mp_reach, nil
}

func EncodeLabeledIPV4_MP_REACH_NLRI(nh uint32,
	flags RouteFlags, nlris []IPV4_NLRI) ([]byte, error) {
	if len(nlris) < 1 {
		return nil, fmt.Errorf("zero length NLRIs slice\n")
	}
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
	var reserved uint8
	err = binary.Write(buf, binary.BigEndian, &reserved)
	if err != nil {
		return nil, err
	}
	if flags.WithPathId {
		/* same logic as above for ipv4 nlri */
		err = binary.Write(buf, binary.BigEndian, &nlris[0].PathID)
		if err != nil {
			return nil, err
		}
	}
	encNLRI, err := EncodeIPv4NLRI(flags, nlris)
	if err != nil {
		return nil, err
	}
	mp_reach := append(buf.Bytes(), encNLRI...)
	return mp_reach, nil
}

func DecodeIPV4_MP_REACH_NLRI(flags RouteFlags,
	data []byte, mpHdr MP_REACH_NLRI_HDR) (uint32, []IPV4_NLRI, error) {
	var nh uint32
	err := binary.Read(bytes.NewReader(data), binary.BigEndian, &nh)
	if err != nil {
		return nh, nil, err
	}
	/*
		one_octet -> reserved field
	*/
	data = data[mpHdr.NHLength+ONE_OCTET:]
	nlris, err := DecodeIPv4NLRI(flags, data)
	if err != nil {
		return nh, nil, fmt.Errorf("cant decode ipv4 nlri: %v\n", err)
	}
	return nh, nlris, nil
}

func EncodeIPV4_MP_UNREACH_NLRI(flags RouteFlags, nlris []IPV4_NLRI) ([]byte, error) {
	/*
		compare to the mp_reach_nlri this one (nlris above) could be
		zero len when this path_attr been used as EOR marker
	*/
	buf := new(bytes.Buffer)
	mpUnreachHdr := MP_UNREACH_NLRI_HDR{AFI: MP_AFI_IPV4, SAFI: MP_SAFI_UCAST}
	err := binary.Write(buf, binary.BigEndian, &mpUnreachHdr)
	if err != nil {
		return nil, err
	}
	encNLRI, err := EncodeIPv4NLRI(flags, nlris)
	if err != nil {
		return nil, err
	}
	mp_unreach := append(buf.Bytes(), encNLRI...)
	return mp_unreach, nil
}

func EncodeLabeledIPV4_MP_UNREACH_NLRI(flags RouteFlags, nlris []IPV4_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	mpUnreachHdr := MP_UNREACH_NLRI_HDR{AFI: MP_AFI_IPV4, SAFI: MP_SAFI_LABELED}
	err := binary.Write(buf, binary.BigEndian, &mpUnreachHdr)
	if err != nil {
		return nil, err
	}
	encNLRI, err := EncodeIPv4NLRI(flags, nlris)
	if err != nil {
		return nil, err
	}
	mp_unreach := append(buf.Bytes(), encNLRI...)
	return mp_unreach, nil
}
