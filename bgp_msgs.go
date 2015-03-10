package bgp

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	MAX_MSG_SIZE = 4096
	MSG_HDR_SIZE = 19
)

/*
	All details about headers format etc could be found in rfc 4271
*/

type MsgHeader struct {
	Marker [16]byte
	Length uint16
	Type   uint8
}

type OpenMsg struct {
	Version        uint8
	MyASN          uint16
	HoldTime       uint16
	BGPID          uint32
	OptParamLength uint8
	//OptParamWill be in separate struct
}

type OptionalParamHeader struct {
	ParamType   uint8
	ParamLength uint8
}

func DecodeMsgHeader(msg []byte) (MsgHeader, error) {
	msgHdr := MsgHeader{}
	if len(msg) < MSG_HDR_SIZE {
		return msgHdr, errors.New("msg too short")
	}
	err := binary.Read(bytes.NewReader(msg), binary.BigEndian, &msgHdr)
	if err != nil {
		return msgHdr, errors.New("cant decode msg header")
	}
	if msgHdr.Length > MAX_MSG_SIZE {
		return msgHdr, errors.New("msg too long")
	}
	return msgHdr, nil
}

func EncodeMsgHeader(msgHeader *MsgHeader) ([]byte, error) {
	// 16 bytes all of 1s
	msgHeader.Marker = [16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, msgHeader)
	if err != nil {
		return nil, errors.New("cant encode msg header")
	}
	return buf.Bytes(), nil
}

func DecodeOpenMsg(msg []byte) (OpenMsg, error) {
	openMsg := OpenMsg{}
	err := binary.Read(bytes.NewReader(msg), binary.BigEndian, &openMsg)
	if err != nil {
		return openMsg, errors.New("cant decode open msg")
	}
	return openMsg, nil
}

func EncodeOpenMsg(openMsg *OpenMsg) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, openMsg)
	if err != nil {
		return nil, errors.New("cant encode open msg")
	}
	return buf.Bytes(), nil
}

func DecodeOptionalParamHeader(msg []byte) (OptionalParamHeader, error) {
	optParamHdr := OptionalParamHeader{}
	err := binary.Read(bytes.NewReader(msg), binary.BigEndian, &optParamHdr)
	if err != nil {
		return optParamHdr, errors.New("cant decode optional param header")
	}
	return optParamHdr, nil

}

func EncodeOptionalParamHeader(optParamHdr *OptionalParamHeader) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, optParamHdr)
	if err != nil {
		return nil, errors.New("cant encode optional param header")
	}
	return buf.Bytes(), nil
}
