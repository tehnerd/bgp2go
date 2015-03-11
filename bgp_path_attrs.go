package bgp

import (
	"bytes"
	"encoding/binary"
	"errors"
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
