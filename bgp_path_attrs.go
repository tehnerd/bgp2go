package bgp

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type PathAttrHdr struct {
	AttrType       uint16
	AttrFlags      uint8
	AttrTypeCode   uint8
	AttrLength     uint16
	ExtendedLength bool
}

func DecodePathAttrHdr(msg []byte, pathAttr *PathAttrHdr) error {
	reader := bytes.NewReader(msg)
	pathAttr.ExtendedLength = false
	err := binary.Read(reader, binary.BigEndian, &(pathAttr.AttrType))
	if err != nil {
		return errors.New("cant decode update msg")
	}
	pathAttr.AttrFlags = uint8((pathAttr.AttrType >> 8))
	pathAttr.AttrTypeCode = uint8((pathAttr.AttrType & 255))
	if pathAttr.AttrFlags&(1<<4) == 1 {
		err = binary.Read(reader, binary.BigEndian, &(pathAttr.AttrLength))
		if err != nil {
			return errors.New("cant decode update msg")
		}
		pathAttr.ExtendedLength = true
	} else {
		tmpLength := uint8(0)
		err = binary.Read(reader, binary.BigEndian, &(tmpLength))
		if err != nil {
			return errors.New("cant decode update msg")
		}
		pathAttr.AttrLength = uint16(tmpLength)
	}
	return nil
}
