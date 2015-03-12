package bgp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (

	//Misc const
	MAX_MSG_SIZE      = 4096
	MSG_HDR_SIZE      = 19
	ONE_OCTET_SHIFT   = 1
	TWO_OCTET_SHIFT   = 2
	THREE_OCTET_SHIFT = 3
	FOUR_OCTET_SHIFT  = 4

	// BGP's msg's types
	BGP_OPEN_MSG         = 1
	BGP_UPDATE_MSG       = 2
	BGP_NOTIFICATION_MSG = 3
	BGP_KEEPALIVE_MSG    = 4
	BGP_ROUTEREFRESH_MSG = 5

	/* BGP Error codes and subcodes */
	BGP_MSG_HEADER_ERROR   = 1
	BGP_OPEN_MSG_ERROR     = 2
	BGP_UPDATE_MSG_ERROR   = 3
	BGP_HOLD_TIMER_EXPIRED = 4
	BGP_FSM_ERROR          = 5
	BGP_CASE_ERROR         = 6

	/*MSG Header subcodes */
	BGP_MH_ERROR_NOTSYNC   = 1
	BGP_MH_ERROR_BADLENGTH = 2
	BGP_MH_ERROR_BADTYPE   = 3

	/*Open msg subcodes */
	BGP_OM_ERROR_USUP_VER     = 1
	BGP_OM_ERROR_BAD_PEER_AS  = 2
	BGP_OM_ERROR_BGP_ID       = 3
	BGP_OM_ERROR_USUP_OPT     = 4
	BGP_OM_ERROR_DEPRICATED   = 5
	BGP_OM_ERROR_UACCEPT_HOLD = 6

	/* Update msg subcodes */
	BGP_UPD_ERROR_MAILFORMED_ATTR    = 1
	BGP_UPD_ERROR_UNREC_WELL_KNOWN   = 2
	BGP_UPD_ERROR_MISSING_WELL_KNOWN = 3
	BGP_UPD_ERROR_ATTR_FLAG          = 4
	BGP_UPD_ERROR_ATTR_LENGTH        = 5
	BGP_UPD_ERROR_INVALID_ORIGIN     = 6
	BGP_UPD_ERROR_DEPRICATED         = 7
	BGP_UPD_ERROR_INVALID_NH         = 8
	BGP_UPD_ERROR_OPT_ATTR           = 9
	BGP_UPD_ERROR_INVALID_NETWORK    = 10
	BGP_UPD_ERROR_MAILFORMED_AS_PATH = 11

	/* Case errors subcodes */
	BGP_CASE_ERROR_GENERIC   = 0
	BGP_CASE_ERROR_COLLISION = 7
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

type NotificationMsg struct {
	ErrorCode    uint8
	ErrorSubcode uint8
	/*
	   according to 4271 there also could be data field of variable length,
	   but so far havent seen that anyone actually uses it;
	   removing it greatly simplifies notification encoding and shouldnt
	   break anything, coz during notification rcving we must tear down the session anyway
	   and for that purpose ErrorCode & Subcodes fields should be enought;
	   data field could be added in future, if there are going to be any demands
	*/
}

type IPv4Route struct {
	PrefixLength uint8
	Prefix       uint32
}

type PathSegment struct {
	PSType   uint8
	PSLength uint8
	PSValue  []uint16
}

type Agregator struct {
	ASN         uint16
	AgregatorID uint32
}

type IPV4_NLRI struct {
	Length uint8
	Prefix uint32
}

type BGPRoute struct {
	ORIGIN uint8
	//TODO: could be more that 1 path segment
	AS_PATH         PathSegment
	NEXT_HOP        []byte
	MULTI_EXIT_DISC uint32
	LOCAL_PREF      uint32
	ATOMIC_AGGR     bool
	AGGREGATOR      Agregator
	Routes          []IPV4_NLRI
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

func AddAttrToRoute(bgpRoute *BGPRoute, pathAttr *PathAttr) error {
	reader := bytes.NewReader(pathAttr.Data)
	err := errors.New("placeholder")
	switch pathAttr.AttrTypeCode {
	case BA_ORIGIN:
		err = binary.Read(reader, binary.BigEndian, &(bgpRoute.ORIGIN))
		if err != nil {
			return fmt.Errorf("cant decode ORIGIN Attr: %v\n", err)
		}
	case BA_MULTI_EXIT_DISC:
		err = binary.Read(reader, binary.BigEndian, &(bgpRoute.MULTI_EXIT_DISC))
		if err != nil {
			return fmt.Errorf("cant decode MED Attr: %v\n", err)
		}

	case BA_LOCAL_PREF:
		err = binary.Read(reader, binary.BigEndian, &(bgpRoute.LOCAL_PREF))
		if err != nil {
			return fmt.Errorf("cant decode LOCAL_PREF Attr: %v\n", err)
		}
	case BA_ATOMIC_AGGR:
		bgpRoute.ATOMIC_AGGR = true
	case BA_NEXT_HOP:
		bgpRoute.NEXT_HOP = append(bgpRoute.NEXT_HOP, pathAttr.Data...)
	case BA_AS_PATH:
		if pathAttr.AttrLength != 0 {
			err = binary.Read(reader, binary.BigEndian, &(bgpRoute.AS_PATH.PSType))
			err = binary.Read(reader, binary.BigEndian, &(bgpRoute.AS_PATH.PSLength))
			if err != nil {
				return fmt.Errorf("cant decode ASPathLen & Type: %v\n", err)
			}
			asn := uint16(0)
			for cntr := 0; cntr < int(bgpRoute.AS_PATH.PSLength); cntr++ {
				err = binary.Read(reader, binary.BigEndian, &asn)
				if err != nil {
					return fmt.Errorf("cant decode ASPathLen ASNS: %v\n", err)
				}
				bgpRoute.AS_PATH.PSValue = append(bgpRoute.AS_PATH.PSValue, asn)
			}
		} else {
			return nil
		}
	}
	return nil
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
func DecodeUpdateMsg(msg []byte) (BGPRoute, error) {
	updMsgLen := UpdateMsgLengths{}
	bgpRoute := BGPRoute{}
	offset := MSG_HDR_SIZE
	err := binary.Read(bytes.NewReader(msg[offset:]), binary.BigEndian, &(updMsgLen.WithdrawRoutesLength))
	if err != nil {
		return bgpRoute, fmt.Errorf("cant decode update msg withdraw length: %v\n", err)
	}
	offset = MSG_HDR_SIZE + TWO_OCTET_SHIFT + int(updMsgLen.WithdrawRoutesLength)
	//TODO: read withdraw routes
	err = binary.Read(bytes.NewReader(msg[offset:]), binary.BigEndian, &(updMsgLen.TotalPathAttrsLength))
	if err != nil {
		return bgpRoute, fmt.Errorf("cant decode update msg total path attr length: %v\n", err)
	}
	pathAttr := PathAttr{}
	offset = 2*TWO_OCTET_SHIFT + int(updMsgLen.WithdrawRoutesLength) + MSG_HDR_SIZE
	attrsEndOffset := offset + int(updMsgLen.TotalPathAttrsLength)
	for offset < attrsEndOffset {
		err = DecodePathAttr(msg[offset:], &pathAttr)
		if err != nil {
			return bgpRoute, fmt.Errorf("cant decode update msg attribute: %v\n", err)
		}
		err := AddAttrToRoute(&bgpRoute, &pathAttr)
		if err != nil {
			return bgpRoute, fmt.Errorf("cant update msg attribute data: %v\n", err)
		}
		//Size of path's attr heaer either 3 of 4 octets
		if pathAttr.ExtendedLength {
			offset = offset + FOUR_OCTET_SHIFT + int(pathAttr.AttrLength)
		} else {
			offset = offset + THREE_OCTET_SHIFT + int(pathAttr.AttrLength)
		}
	}
	offset = (2*TWO_OCTET_SHIFT + int(updMsgLen.WithdrawRoutesLength) +
		int(updMsgLen.TotalPathAttrsLength) + MSG_HDR_SIZE)
	//right now we are trying to implement minimal functionality. so that means ipv4 only
	//TODO: ipv6 must must (or even MP-BGP)
	prefix := IPV4_NLRI{}
	for offset < len(msg) {
		err = binary.Read(bytes.NewReader(msg[offset:]), binary.BigEndian, &(prefix.Length))
		if err != nil {
			return bgpRoute, fmt.Errorf("cant decode update msg prefix length: %v\n", err)
		}
		offset += ONE_OCTET_SHIFT
		//awsm trick from BIRD
		prefixBits := int((prefix.Length + 7) / 8)
		prefixPart := msg[offset : offset+prefixBits]
		for cntr := prefixBits; cntr < 4; cntr++ {
			prefixPart = append(prefixPart, byte(0))
		}
		err = binary.Read(bytes.NewReader(prefixPart), binary.BigEndian, &(prefix.Prefix))
		if err != nil {
			return bgpRoute, fmt.Errorf("cant decode update msg prefix: %v\n", err)
		}

		bgpRoute.Routes = append(bgpRoute.Routes, prefix)
		//size of prefix len + ipv4 address
		offset += FOUR_OCTET_SHIFT
	}
	return bgpRoute, nil
}

func (bgpRoute *BGPRoute) AddV4NextHop(ipv4 string) error {
	v4addr, err := IPv4ToUint32(ipv4)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, &v4addr)
	if err != nil {
		return err
	}
	bgpRoute.NEXT_HOP = buf.Bytes()
	return nil
}

func DecodeV4NextHop(bgpRoute *BGPRoute) (uint32, error) {
	reader := bytes.NewReader(bgpRoute.NEXT_HOP)
	ipv4 := uint32(0)
	err := binary.Read(reader, binary.BigEndian, &ipv4)
	if err != nil {
		return ipv4, fmt.Errorf("cant decove ipv4 next hop: %v\n", err)
	}
	return ipv4, nil
}

//TODO: add withdraw
func EncodeUpdateMsg(bgpRoute *BGPRoute) ([]byte, error) {
	encodedUpdate := make([]byte, 0)
	buf := new(bytes.Buffer)
	updMsgLen := UpdateMsgLengths{WithdrawRoutesLength: 0}
	if len(bgpRoute.NEXT_HOP) == 0 {
		return nil, fmt.Errorf("no mandatory attr(next-hop) in bgp update\n")
	}
	encodedAttrs, err := EncodeBGPRouteAttrs(bgpRoute)
	if err != nil {
		return nil, fmt.Errorf("cant encode path attributes: %v\n", err)
	}
	//placeholder
	updMsgLen.TotalPathAttrsLength = uint16(len(encodedAttrs))
	err = binary.Write(buf, binary.BigEndian, &updMsgLen.WithdrawRoutesLength)
	if err != nil {
		return nil, fmt.Errorf("cant encode withdar routes length\n")
	}
	//TODO: add withdraw
	encodedUpdate = append(encodedUpdate, buf.Bytes()...)
	err = binary.Write(buf, binary.BigEndian, &updMsgLen.TotalPathAttrsLength)
	if err != nil {
		return nil, fmt.Errorf("cant encode total path attrs length\n")
	}
	encodedUpdate = append(encodedUpdate, buf.Bytes()[TWO_OCTET_SHIFT+updMsgLen.WithdrawRoutesLength:]...)
	encodedUpdate = append(encodedUpdate, encodedAttrs...)
	msgHdr := MsgHeader{Type: BGP_UPDATE_MSG, Length: uint16(len(encodedUpdate))}
	encMsgHdr, err := EncodeMsgHeader(&msgHdr)
	if err != nil {
		return nil, fmt.Errorf("cant encode update msg hdr: %v\n", err)
	}
	encodedUpdate = append(encMsgHdr, encodedUpdate...)
	return encodedUpdate, nil
}

func DecodeNotificationMsg(msg []byte) (NotificationMsg, error) {
	offset := MSG_HDR_SIZE
	notification := NotificationMsg{}
	reader := bytes.NewReader(msg[offset:])
	err := binary.Read(reader, binary.BigEndian, &notification)
	if err != nil {
		return notification, errors.New("cant decode notification")
	}
	return notification, nil
}

func EncodeNotificationMsg(notification *NotificationMsg) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, notification)
	if err != nil {
		return nil, fmt.Errorf("can encode notification msg: %v\n", err)
	}
	return buf.Bytes(), nil
}

func GenerateKeepalive() []byte {
	keepAlive := MsgHeader{}
	keepAlive.Length = MSG_HDR_SIZE
	keepAlive.Type = BGP_KEEPALIVE_MSG
	kaMsg, _ := EncodeMsgHeader(&keepAlive)
	return kaMsg
}