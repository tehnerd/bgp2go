package bgp

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (

	//Misc const
	MAX_MSG_SIZE     = 4096
	MSG_HDR_SIZE     = 19
	TWO_OCTET_SHIFT  = 2
	FOUR_OCTET_SHIFT = 4
	ONE_OCTET_SHIFT  = 1

	// BGP's msg's types
	BGP_OPEN_MSG         = 1
	BGP_UPDATE_MSG       = 2
	BGP_NOTIFICATION_MSG = 3
	BGP_KEEPALIVE_MSG    = 4
	BGP_ROUTEREFRESH_MSG = 5
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

//TODO: add optional capabilities structs; such as 32bit asn; rr etc

type UpdateMsgLengths struct {
	WithdrawRoutesLength uint16
	//WithdrawRoutes variable
	TotalPathAttrsLength uint16
	//Path attrs variable
	//NLRI variable
}

type Route struct {
	PrefixLength uint8
	//Prefix variable
}

type PathAttrsHdr struct {
	AttrFlags  uint8
	AttrType   uint8
	AttrLength uint16
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

//will incremently add features; update msg, compare to other ones, has lots of variable length fields
func DecodeUpdateMsg(msg []byte) (UpdateMsgLengths, error) {
	var updMsgLen = UpdateMsgLengths{}
	err := binary.Read(bytes.NewReader(msg), binary.BigEndian, &(updMsgLen.WithdrawRoutesLength))
	if err != nil {
		return updMsgLen, errors.New("cant decode update msg")
	}
	msg = msg[TWO_OCTET_SHIFT+updMsgLen.WithdrawRoutesLength:]
	err = binary.Read(bytes.NewReader(msg), binary.BigEndian, &(updMsgLen.TotalPathAttrsLength))
	if err != nil {
		return updMsgLen, errors.New("cant decode update msg")
	}
	return updMsgLen, nil
}
