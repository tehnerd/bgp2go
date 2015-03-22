package bgp2go

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
	MIN_OPEN_MSG_SIZE = 29
	OPEN_MSG_HDR_SIZE = 10
	ONE_OCTET_SHIFT   = 1
	TWO_OCTET_SHIFT   = 2
	THREE_OCTET_SHIFT = 3
	FOUR_OCTET_SHIFT  = 4
	ONE_OCTET         = 1
	TWO_OCTETS        = 2
	FOUR_OCTETS       = 4

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

	/* BGP Generic Error */
	BGP_GENERIC_ERROR = 0
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
	Hdr    OpenMsgHdr
	MPCaps []MPCapability
}
type OpenMsgHdr struct {
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
	AS_PATH  PathSegment
	NEXT_HOP []byte
	//TODO: mb it's better to use generic nh([]byte; above)
	NEXT_HOPv6       IPv6Addr
	MULTI_EXIT_DISC  uint32
	LOCAL_PREF       uint32
	ATOMIC_AGGR      bool
	AGGREGATOR       Agregator
	Routes           []IPV4_NLRI
	RoutesV6         []IPV6_NLRI
	WithdrawRoutes   []IPV4_NLRI
	WithdrawRoutesV6 []IPV6_NLRI
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
	err := binary.Read(bytes.NewReader(msg), binary.BigEndian, &openMsg.Hdr)
	if err != nil {
		return openMsg, errors.New("cant decode open msg")
	}
	if openMsg.Hdr.OptParamLength > 0 {
		msg = msg[OPEN_MSG_HDR_SIZE:]
		for len(msg) > 0 {
			optParamHdr, optParam, err := DecodeOptionalParamHeader(msg)
			if err != nil {
				return openMsg, fmt.Errorf("cant decode opt param hdr: %v\n", err)
			}
			msg = msg[TWO_OCTETS+optParamHdr.ParamLength:]
			if optParamHdr.ParamType == CAPABILITIES_OPTIONAL_PARAM {
				capHdr, capability, err := DecodeCapability(optParam)
				if err != nil {
					return openMsg, fmt.Errorf("cant decode capability hdr: %v\n", err)
				}
				if capHdr.Code == CAPABILITY_MP_EXTENSION {
					mpCap, err := DecodeMPCapability(capability)
					if err != nil {
						return openMsg, fmt.Errorf("cant decode mp capability: %v\n", err)
					}
					openMsg.MPCaps = append(openMsg.MPCaps, mpCap)
				}
			}
		}
	}
	return openMsg, nil
}

func EncodeOpenMsg(openMsg *OpenMsg) ([]byte, error) {
	buf := new(bytes.Buffer)
	encodedOptParams := make([]byte, 0)
	for _, mpCap := range openMsg.MPCaps {
		encMPCap, err := EncodeMPCapability(mpCap)
		if err != nil {
			return nil, fmt.Errorf("cant encode mp cap: %v\n", err)
		}
		encCap, err := EncodeCapability(Capability{Code: CAPABILITY_MP_EXTENSION},
			encMPCap)
		if err != nil {
			return nil, fmt.Errorf("cant encode capability: %v\n", err)
		}
		encParamHdr, err := EncodeOptionalParamHeader(OptionalParamHeader{
			ParamType:   CAPABILITIES_OPTIONAL_PARAM,
			ParamLength: uint8(len(encCap)),
		})
		encodedOptParams = append(encodedOptParams, encParamHdr...)
		encodedOptParams = append(encodedOptParams, encCap...)
	}
	openMsg.Hdr.OptParamLength = uint8(len(encodedOptParams))
	err := binary.Write(buf, binary.BigEndian, openMsg.Hdr)
	if err != nil {
		return nil, errors.New("cant encode open msg")
	}
	encodedOpen := buf.Bytes()
	msgHdr := MsgHeader{Type: BGP_OPEN_MSG, Length: MIN_OPEN_MSG_SIZE +
		uint16(openMsg.Hdr.OptParamLength)}
	encodedHdr, err := EncodeMsgHeader(&msgHdr)
	if err != nil {
		return nil, fmt.Errorf("cant encode open msg: %v\n", err)
	}
	encodedOpen = append(encodedHdr, encodedOpen...)
	encodedOpen = append(encodedOpen, encodedOptParams...)
	return encodedOpen, nil
}

func DecodeOptionalParamHeader(msg []byte) (OptionalParamHeader, []byte, error) {
	optParamHdr := OptionalParamHeader{}
	if len(msg) < TWO_OCTETS {
		return optParamHdr, nil, fmt.Errorf("opt param len is not enough for decoding\n")
	}
	err := binary.Read(bytes.NewReader(msg), binary.BigEndian, &optParamHdr)
	if err != nil {
		return optParamHdr, nil, fmt.Errorf("cant decode optional param header: %v\n", err)
	}
	if len(msg) < (TWO_OCTETS + int(optParamHdr.ParamLength)) {
		return optParamHdr, nil, fmt.Errorf("opt param len is not enough for decoding\n")
	}
	return optParamHdr, msg[TWO_OCTETS : TWO_OCTETS+optParamHdr.ParamLength], nil

}

func EncodeOptionalParamHeader(optParamHdr OptionalParamHeader) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, optParamHdr)
	if err != nil {
		return nil, errors.New("cant encode optional param header")
	}
	return buf.Bytes(), nil
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
		//TODO: as_path can has more than one path segment
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

//will incremently add features; update msg, compare to other ones, has lots of variable length fields
func DecodeUpdateMsg(msg []byte) (BGPRoute, error) {
	updMsgLen := UpdateMsgLengths{}
	bgpRoute := BGPRoute{}
	offset := MSG_HDR_SIZE
	err := binary.Read(bytes.NewReader(msg[offset:]), binary.BigEndian, &(updMsgLen.WithdrawRoutesLength))
	if err != nil {
		return bgpRoute, fmt.Errorf("cant decode update msg withdraw length: %v\n", err)
	}
	offset = MSG_HDR_SIZE + TWO_OCTET_SHIFT
	withdrawRoutes, err := DecodeIPv4Route(offset, offset+int(updMsgLen.WithdrawRoutesLength),
		msg)
	if err != nil {
		return bgpRoute, err
	}
	bgpRoute.WithdrawRoutes = withdrawRoutes
	offset = MSG_HDR_SIZE + TWO_OCTET_SHIFT + int(updMsgLen.WithdrawRoutesLength)
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
	routes, err := DecodeIPv4Route(offset, len(msg), msg)
	if err != nil {
		return bgpRoute, err
	}
	bgpRoute.Routes = routes
	return bgpRoute, nil
}

func DecodeIPv4Route(offset, finalPosition int, msg []byte) ([]IPV4_NLRI, error) {
	prefix := IPV4_NLRI{}
	prefixList := make([]IPV4_NLRI, 0)
	for offset < finalPosition {
		err := binary.Read(bytes.NewReader(msg[offset:]), binary.BigEndian, &(prefix.Length))
		if err != nil {
			return prefixList, fmt.Errorf("cant decode update msg prefix length: %v\n", err)
		}
		offset += ONE_OCTET_SHIFT
		//awsm trick from BIRD
		prefixBits := int((prefix.Length + 7) / 8)
		prefixPart := make([]byte, 0)
		prefixPart = append(prefixPart, msg[offset:offset+prefixBits]...)
		for cntr := prefixBits; cntr < 4; cntr++ {
			prefixPart = append(prefixPart, byte(0))
		}
		err = binary.Read(bytes.NewReader(prefixPart), binary.BigEndian, &(prefix.Prefix))
		if err != nil {
			return prefixList, fmt.Errorf("cant decode update msg prefix: %v\n", err)
		}
		prefixList = append(prefixList, prefix)
		offset += prefixBits
	}
	return prefixList, nil
}

func (bgpRoute *BGPRoute) AddV4NextHop(ipv4 string) error {
	v4addr, err := IPv4ToUint32(ipv4)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, &v4addr)
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

func EncodeUpdateMsg(bgpRoute *BGPRoute) ([]byte, error) {
	encodedUpdate := make([]byte, 0)
	buf := new(bytes.Buffer)
	updMsgLen := UpdateMsgLengths{}
	encodedAttrs, err := EncodeBGPRouteAttrs(bgpRoute)
	if err != nil {
		return nil, fmt.Errorf("cant encode path attributes: %v\n", err)
	}
	encodedRoutes, err := EncodeIPv4Route(bgpRoute.Routes)
	if err != nil {
		return nil, fmt.Errorf("cant encoded bgp routes: %v\n", err)
	}
	updMsgLen.TotalPathAttrsLength = uint16(len(encodedAttrs))
	err = binary.Write(buf, binary.BigEndian, &updMsgLen.WithdrawRoutesLength)
	if err != nil {
		return nil, fmt.Errorf("cant encode withdar routes length\n")
	}
	encodedUpdate = append(encodedUpdate, buf.Bytes()...)
	err = binary.Write(buf, binary.BigEndian, &updMsgLen.TotalPathAttrsLength)
	if err != nil {
		return nil, fmt.Errorf("cant encode total path attrs length\n")
	}
	encodedUpdate = append(encodedUpdate, buf.Bytes()[TWO_OCTET_SHIFT:]...)
	encodedUpdate = append(encodedUpdate, encodedAttrs...)
	encodedUpdate = append(encodedUpdate, encodedRoutes...)
	msgHdr := MsgHeader{Type: BGP_UPDATE_MSG, Length: MSG_HDR_SIZE + uint16(len(encodedUpdate))}
	encMsgHdr, err := EncodeMsgHeader(&msgHdr)
	if err != nil {
		return nil, fmt.Errorf("cant encode update msg hdr: %v\n", err)
	}
	encodedUpdate = append(encMsgHdr, encodedUpdate...)
	return encodedUpdate, nil
}

//TODO: mp_unreach caries withdraw routes in path_attr
func EncodeWithdrawUpdateMsg(bgpRoute *BGPRoute) ([]byte, error) {
	encodedUpdate := make([]byte, 0)
	buf := new(bytes.Buffer)
	encodedWithdrawRoutes, err := EncodeIPv4Route(bgpRoute.WithdrawRoutes)
	if err != nil {
		return nil, fmt.Errorf("cant encode withdraw routes")
	}
	updMsgLen := UpdateMsgLengths{WithdrawRoutesLength: uint16(len(encodedWithdrawRoutes))}
	err = binary.Write(buf, binary.BigEndian, &updMsgLen.WithdrawRoutesLength)
	if err != nil {
		return nil, fmt.Errorf("cant encode withdar routes length\n")
	}
	encodedUpdate = append(encodedUpdate, buf.Bytes()...)
	encodedUpdate = append(encodedUpdate, encodedWithdrawRoutes...)
	err = binary.Write(buf, binary.BigEndian, &updMsgLen.TotalPathAttrsLength)
	if err != nil {
		return nil, fmt.Errorf("cant encode total path attrs length\n")
	}
	encodedUpdate = append(encodedUpdate, buf.Bytes()[TWO_OCTET_SHIFT:]...)
	msgHdr := MsgHeader{Type: BGP_UPDATE_MSG, Length: MSG_HDR_SIZE + uint16(len(encodedUpdate))}
	encMsgHdr, err := EncodeMsgHeader(&msgHdr)
	if err != nil {
		return nil, fmt.Errorf("cant encode update msg hdr: %v\n", err)
	}
	encodedUpdate = append(encMsgHdr, encodedUpdate...)
	return encodedUpdate, nil
}

func EncodeIPv4Route(routesSlice []IPV4_NLRI) ([]byte, error) {
	buf := new(bytes.Buffer)
	routes := make([]byte, 0)
	prefixBits := 0
	notUsedBits := 0
	for _, route := range routesSlice {
		err := binary.Write(buf, binary.BigEndian, route.Length)
		if err != nil {
			return routes, fmt.Errorf("error during encoding routes: %v\n", err)
		}
		err = binary.Write(buf, binary.BigEndian, route.Prefix)
		if err != nil {
			return routes, fmt.Errorf("error during encoding routes: %v\n", err)
		}
		prefixBits = int((route.Length + 7) / 8)
		notUsedBits = FOUR_OCTET_SHIFT - prefixBits
		routes = append(routes, buf.Next(ONE_OCTET_SHIFT+prefixBits)...)
		buf.Next(notUsedBits)
	}
	return routes, nil
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
	encodedNotification := make([]byte, 0)
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, notification)
	if err != nil {
		return nil, fmt.Errorf("can encode notification msg: %v\n", err)
	}
	encodedNotification = append(encodedNotification, buf.Bytes()...)
	msgHdr := MsgHeader{
		Type:   BGP_NOTIFICATION_MSG,
		Length: MSG_HDR_SIZE + uint16(len(encodedNotification))}
	encMsgHdr, err := EncodeMsgHeader(&msgHdr)
	if err != nil {
		return nil, fmt.Errorf("can encode notification msg hdr: %v\n", err)
	}
	encodedNotification = append(encMsgHdr, encodedNotification...)
	return encodedNotification, nil
}

func GenerateKeepalive() []byte {
	keepAlive := MsgHeader{}
	keepAlive.Length = MSG_HDR_SIZE
	keepAlive.Type = BGP_KEEPALIVE_MSG
	kaMsg, _ := EncodeMsgHeader(&keepAlive)
	return kaMsg
}

func GenerateEndOfRIB() []byte {
	encodedUpdate := make([]byte, 0)
	buf := new(bytes.Buffer)
	updMsgLen := UpdateMsgLengths{WithdrawRoutesLength: 0, TotalPathAttrsLength: 0}
	binary.Write(buf, binary.BigEndian, &updMsgLen)
	encodedUpdate = append(encodedUpdate, buf.Bytes()...)
	msgHdr := MsgHeader{Type: BGP_UPDATE_MSG, Length: MSG_HDR_SIZE + uint16(len(encodedUpdate))}
	encMsgHdr, _ := EncodeMsgHeader(&msgHdr)
	encodedUpdate = append(encMsgHdr, encodedUpdate...)
	return encodedUpdate
}
