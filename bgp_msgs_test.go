package bgp2go

import (
	"encoding/hex"
	"fmt"
	"testing"
)

const (
	hexOpenMsg                   = "ffffffffffffffffffffffffffffffff003b0104fde8005a0a0000021e02060104000100010202800002020200020440020078020641040000fde8"
	hexUpdate1                   = "ffffffffffffffffffffffffffffffff00360200000015400101004002004003040a0000024005040000006420010101012001010102"
	hexUpdate2                   = "ffffffffffffffffffffffffffffffff0038020000001c400101004002004003040a00000280040400000078400504000000642001010103"
	hexUpdate3                   = "ffffffffffffffffffffffffffffffff00170200000000"
	hexUpdate4                   = "ffffffffffffffffffffffffffffffff005102000000364001010240021a02060000000100000002000000030000000400000005000000064003040a00000240050400000064c00804ffff000118010b01"
	hexKA                        = "ffffffffffffffffffffffffffffffff001304"
	hexNotification              = "ffffffffffffffffffffffffffffffff0015030607"
	hexIPv6NLRI                  = "302a00bdc0e003"
	hexIPv6_MP_REACH             = "00020110200107f800200101000000000245018000302a00bdc0e003"
	hexIPv6_MP_REACH_NLRI_PA     = "900e001c00020110200107f800200101000000000245018000302a00bdc0e003"
	hexLabeledIPv4_MP_REACH_NLRI = "ffffffffffffffffffffffffffffffff007702000000604001010040020602010000ff7880040400000001c0080cff780001ff780002ff780064900e0039000104040a004e070038494701c0a8010638494401c0a8010338494501c0a8010438494601c0a8010538494301c0a8010238494201c0a80101"
	hexJuniperOpen               = "ffffffffffffffffffffffffffffffff003b0104ff79005ac0a801081e02060104000100040202800002020200020440020078020641040000ff79"
	hexEndOfRibv4                = "ffffffffffffffffffffffffffffffff001e0200000007900f0003000104"
)

func TestDecodeMsgHeader(t *testing.T) {
	encodedOpen, _ := hex.DecodeString(hexOpenMsg)
	_, err := DecodeMsgHeader(encodedOpen)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during bgp msg header decoding")
		return
	}
}

func TestEncodeMsgHeader(t *testing.T) {
	encodedOpen, _ := hex.DecodeString(hexOpenMsg)
	msgHdr := MsgHeader{Length: 59, Type: 1}
	encMsgHdr, err := EncodeMsgHeader(&msgHdr)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during bgp msg header encoding")
		return
	}
	if len(encMsgHdr) != MSG_HDR_SIZE {
		fmt.Println(len(encMsgHdr))
		fmt.Println(encMsgHdr)
		t.Errorf("error in len of encoded hdr")
		return
	}
	for cntr := 0; cntr < len(encMsgHdr); cntr++ {
		if encMsgHdr[cntr] != encodedOpen[cntr] {
			t.Errorf("byte of encoded msg is not equal to etalon's msg")
			return
		}
	}
}

func TestDecodeOpenMsg(t *testing.T) {
	encodedOpen, _ := hex.DecodeString(hexOpenMsg)
	openMsg, err := DecodeOpenMsg(encodedOpen[MSG_HDR_SIZE:])
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during open msg decoding: %v\n", err)
		return
	}
	fmt.Printf("%#v\n", openMsg)
}

func TestDecodeJuniperOpenMsg(t *testing.T) {
	encodedOpen, _ := hex.DecodeString(hexJuniperOpen)
	openMsg, err := DecodeOpenMsg(encodedOpen[MSG_HDR_SIZE:])
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during open msg decoding: %v\n", err)
		return
	}
	fmt.Printf("%#v\n", openMsg)
}

func TestEncodeMPcapability(t *testing.T) {
	mpCap := MPCapability{AFI: 1, SAFI: 1}
	encMpCap, err := EncodeMPCapability(mpCap)
	if err != nil {
		t.Errorf("cant encode mpCap")
		return
	}
	encCap, err := EncodeCapability(Capability{Code: CAPABILITY_MP_EXTENSION}, encMpCap)
	if err != nil {
		t.Errorf("cant encode capability")
		return
	}
	capability, data, err := DecodeCapability(encCap)
	if capability.Code != CAPABILITY_MP_EXTENSION {
		t.Errorf("error during capability decoding")
		return
	}
	if err != nil {
		t.Errorf("can decode encoded capability")
		return
	}
	decMpCap, err := DecodeMPCapability(data)
	if err != nil {
		t.Errorf("cant decode encoded mp capability")
		return
	}
	if decMpCap.AFI != mpCap.AFI || decMpCap.SAFI != mpCap.SAFI {
		t.Errorf("error during enc/dec of mp cap")
		return
	}
}

func TestEncodeOpenWithMPcapabilityAndASN4(t *testing.T) {
	capList := []MPCapability{
		MPCapability{AFI: MP_AFI_IPV4, SAFI: MP_SAFI_UCAST},
		MPCapability{AFI: MP_AFI_IPV6, SAFI: MP_SAFI_UCAST}}
	openMsg := OpenMsg{Hdr: OpenMsgHdr{Version: 4, MyASN: 65000, HoldTime: 90, BGPID: 167772162}}
	openMsg.MPCaps = append(openMsg.MPCaps, capList...)
	openMsg.Caps.SupportASN4 = true
	openMsg.Caps.ASN4 = 65000
	data, err := EncodeOpenMsg(&openMsg)
	if err != nil {
		t.Errorf("cant encode open msg: %v\n", err)
		return
	}
	_, err = DecodeOpenMsg(data[MSG_HDR_SIZE:])
	if err != nil {
		t.Errorf("cant decoded encoded msg: %v\n", err)
		return
	}
}

func TestEncodeOpenMsg(t *testing.T) {
	encodedOpen, _ := hex.DecodeString(hexOpenMsg)
	openMsg := OpenMsg{Hdr: OpenMsgHdr{Version: 4, MyASN: 65000, HoldTime: 90, BGPID: 167772162, OptParamLength: 30}}
	encOpenMsg, err := EncodeOpenMsg(&openMsg)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during open msg  encoding")
		return
	}
	//HACKISH TEST; we dont know how to encode all of the opt params and caps in etalon msg
	//so here we only tests how we have encoded ans,holdtime etc
	for cntr := MSG_HDR_SIZE; cntr < MIN_OPEN_MSG_SIZE-2; cntr++ {
		if encOpenMsg[cntr] != encodedOpen[cntr] {
			t.Errorf("byte of encoded msg is not equal to etalon's msg")
			return
		}
	}
}

func TestDecodeEncodeGR(t *testing.T) {
	encodedOpen, _ := hex.DecodeString(hexOpenMsg)
	openMsg, err := DecodeOpenMsg(encodedOpen[MSG_HDR_SIZE:])
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during open msg decoding: %v\n", err)
		return
	}
	if openMsg.Caps.SupportGR != true {
		t.Errorf("this open msg suppose to have GR enabled\n")
		return
	}
	reEncodedOpen, err := EncodeOpenMsg(&openMsg)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during open msg w/GR encoding: %v\n", err)
		return
	}
	fmt.Println(reEncodedOpen)
	newOpenMsg, err := DecodeOpenMsg(reEncodedOpen[MSG_HDR_SIZE:])
	if err != nil {
		t.Errorf("error during open msg w/GR decoding: %v\n", err)
		return
	}
	if newOpenMsg.Caps.SupportGR != true {
		t.Errorf("error durign GR cap encoding/decoding\n")
		return
	}
}

func TestDecodeUpdateMsg(t *testing.T) {
	encodedUpdate, _ := hex.DecodeString(hexUpdate1)
	_, err := DecodeUpdateMsg(encodedUpdate, &BGPCapabilities{})
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during update  msg decoding")
		return
	}
	//PrintBgpUpdate(&bgpRoute)
	encodedUpdate, _ = hex.DecodeString(hexUpdate2)
	_, err = DecodeUpdateMsg(encodedUpdate, &BGPCapabilities{})
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during update  msg decoding")
		return
	}
	//PrintBgpUpdate(&bgpRoute)
}

func TestDecodeUpdMsgWithAsPath(t *testing.T) {
	encodedUpdate, _ := hex.DecodeString(hexUpdate4)
	_, err := DecodeUpdateMsg(encodedUpdate, &BGPCapabilities{SupportASN4: true})
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during update  msg decoding")
		return
	}
	//PrintBgpUpdate(&bgpRoute)

}

func TestEncodeKeepaliveMsg(t *testing.T) {
	encodedKA, _ := hex.DecodeString(hexKA)
	encKA := GenerateKeepalive()
	for cntr := 0; cntr < len(encKA); cntr++ {
		if encKA[cntr] != encodedKA[cntr] {
			t.Errorf("byte of encoded msg is not equal to etalon's msg")
			return
		}
	}
}

func TestDecodeNotificationMsg(t *testing.T) {
	encodedNotification, _ := hex.DecodeString(hexNotification)
	notification, err := DecodeNotificationMsg(encodedNotification)
	if err != nil {
		t.Errorf("error during notification decoding")
		return
	}
	if notification.ErrorCode != 6 && notification.ErrorSubcode != 7 {
		t.Errorf("error during notification decoding(code and subcode are not equal to etalon)")
		return
	}
}

func TestEncodeNotificationMsg(t *testing.T) {
	encodedNotification, _ := hex.DecodeString(hexNotification)
	notification := NotificationMsg{ErrorCode: BGP_CASE_ERROR, ErrorSubcode: BGP_CASE_ERROR_COLLISION}
	encNotification, err := EncodeNotificationMsg(&notification)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during notification encoding")
		return
	}
	for cntr := 0; cntr < len(encNotification); cntr++ {
		if encNotification[cntr] != encodedNotification[cntr] {
			t.Errorf("byte of encoded msg is not equal to etalon's msg")
			return
		}
	}

}

func TestEncodeUpdateMsg1(t *testing.T) {
	bgpRoute := BGPRoute{
		ORIGIN:          ORIGIN_IGP,
		MULTI_EXIT_DISC: uint32(123),
		LOCAL_PREF:      uint32(11),
		ATOMIC_AGGR:     true,
	}
	p1, _ := IPv4ToUint32("1.92.0.0")
	p2, _ := IPv4ToUint32("11.92.128.0")
	p3, _ := IPv4ToUint32("1.1.1.10")
	bgpRoute.Routes = append(bgpRoute.Routes, IPV4_NLRI{Length: 12, Prefix: p1})
	bgpRoute.Routes = append(bgpRoute.Routes, IPV4_NLRI{Length: 22, Prefix: p2})
	bgpRoute.Routes = append(bgpRoute.Routes, IPV4_NLRI{Length: 32, Prefix: p3})
	err := bgpRoute.AddV4NextHop("10.0.0.2")
	if err != nil {
		fmt.Println(err)
		t.Errorf("cant encode update msg")
		return
	}
	data, err := EncodeUpdateMsg(&bgpRoute)
	if err != nil {
		fmt.Println(err)
		t.Errorf("cant encode update msg")
		return
	}
	bgpRoute2, err := DecodeUpdateMsg(data, &BGPCapabilities{})
	if err != nil {
		fmt.Println(err)
		t.Errorf("cant decode encoded update")
		return
	}
	data2, _ := EncodeUpdateMsg(&bgpRoute2)
	if len(data) != len(data2) {
		t.Errorf("error in encoding/decoding of the same msg")
		return
	}
	for cntr := 0; cntr < len(data); cntr++ {
		if data[cntr] != data2[cntr] {
			t.Errorf("error in encoding/decoding of the same msg")
			return
		}
	}
}

func TestEncodeWithdrawUpdateMsg1(t *testing.T) {
	bgpRoute := BGPRoute{}
	bgpRoute.Community = []uint32{1, 2, 3, 4}
	p4, _ := IPv4ToUint32("192.168.0.0")
	bgpRoute.WithdrawRoutes = append(bgpRoute.WithdrawRoutes, IPV4_NLRI{Length: 16, Prefix: p4})
	data, err := EncodeWithdrawUpdateMsg(&bgpRoute)
	if err != nil {
		fmt.Println(err)
		t.Errorf("cant encode withdraw update msg")
		return
	}
	bgpRoute2, err := DecodeUpdateMsg(data, &BGPCapabilities{})
	if err != nil {
		fmt.Println(err)
		t.Errorf("cant decode withdraw encoded update")
		return
	}
	data2, _ := EncodeWithdrawUpdateMsg(&bgpRoute2)
	if len(data) != len(data2) {
		t.Errorf("error in encoding/decoding of the same withdraw msg")
		return
	}
	for cntr := 0; cntr < len(data); cntr++ {
		if data[cntr] != data2[cntr] {
			t.Errorf("error in encoding/decoding of the same withdraw msg")
			return
		}
	}
	data3, _ := EncodeUpdateMsg(&bgpRoute)
	for cntr := 0; cntr < len(data); cntr++ {
		if data[cntr] != data3[cntr] {
			t.Errorf("error in encoding/decoding of the same withdraw msg")
			return
		}
	}

}

func TestEncodeEndOfRIB(t *testing.T) {
	eor := GenerateEndOfRIB()
	if len(eor) != 23 {
		fmt.Println(eor)
		t.Errorf("error during EndOfRib marker generation")
		return
	}
}

func TestDecodeEndOfRIB(t *testing.T) {
	encodedUpdateEOR, _ := hex.DecodeString(hexEndOfRibv4)
	_, err := DecodeUpdateMsg(encodedUpdateEOR, &BGPCapabilities{SupportASN4: true})
	if err != nil {
		switch err.(type) {
		case EndOfRib:
		default:
			t.Errorf("error during update  msg decoding: %v\n", err)
			return
		}
	}
}

func TestAddPathEncodingDecoding(t *testing.T) {
	addPathList := []AddPathCapability{AddPathCapability{AFI: MP_AFI_IPV4, SAFI: MP_SAFI_UCAST, Flags: uint8(3)}}
	encAddPath, err := EncodeAddPathCapability(addPathList)
	if err != nil {
		t.Errorf("error during add path encoding: %v\n", err)
	}
	_, err = DecodeAddPathCapability(encAddPath[2:])
	if err != nil {
		t.Errorf("error during add path encoding: %v\n", err)
		return
	}

}

/* MP-BGP MP_REACH/UNREACH_NLRI testing */
/* ipv6 */
func TestIPv6StringToUint(t *testing.T) {
	_, err := IPv6StringToAddr("::")
	if err != nil {
		t.Errorf("cant convert ipv6 to ipv6addr\n")
		return
	}
	addr, err := IPv6StringToAddr("fc1:2:3::1")
	if err != nil {
		t.Errorf("cant convert ipv6 to ipv6addr\n")
		return
	}
	ipv6 := IPv6AddrToString(addr)
	fmt.Println(ipv6)
}

func TestIPv6NLRIEncodingDecoding(t *testing.T) {
	encodedIPv6NLRI, _ := hex.DecodeString(hexIPv6NLRI)
	nlri := IPV6_NLRI{Length: 48}
	v6addr, err := IPv6StringToAddr("2a00:bdc0:e003::")
	if err != nil {
		t.Errorf("error during ipv6 addr converting: %v\n", err)
		return
	}
	nlri.Prefix = v6addr
	encIPv6NLRI, err := EncodeIPv6NLRI([]IPV6_NLRI{nlri})
	if err != nil {
		t.Errorf("cant encode ipv6 nlri: %v\n", err)
		return
	}
	fmt.Println(encodedIPv6NLRI)
	fmt.Println(encIPv6NLRI)
	if len(encodedIPv6NLRI) != len(encIPv6NLRI) {
		t.Errorf("len of encoded ipv6 nlri is not equal to len of etalon\n")
		return
	}
	for i := 0; i < len(encIPv6NLRI); i++ {
		if encIPv6NLRI[i] != encodedIPv6NLRI[i] {
			t.Errorf("encoded ipv6 nlri is not equal to etalon")
			return
		}
	}
	decIpv6nlri, err := DecodeIPv6NLRI(encIPv6NLRI)
	if err != nil {
		t.Errorf("cant decode encoded nlri: %v\n", err)
		return
	}
	if decIpv6nlri[0].Length != nlri.Length && decIpv6nlri[0].Prefix != nlri.Prefix {
		fmt.Println(decIpv6nlri)
		fmt.Println(nlri)
		t.Errorf("decoded nlri not equal to original")
		return
	}
}

func TestIPv6MP_REACH_EncodingDecoding(t *testing.T) {
	encodedIPv6MPREACH, _ := hex.DecodeString(hexIPv6_MP_REACH)
	nlri := IPV6_NLRI{Length: 48}
	v6addr, _ := IPv6StringToAddr("2a00:bdc0:e003::")
	v6nh, _ := IPv6StringToAddr("2001:7f8:20:101::245:180")
	nlri.Prefix = v6addr
	encIPv6MPREACH, err := EncodeIPV6_MP_REACH_NLRI(v6nh, []IPV6_NLRI{nlri})
	if err != nil {
		t.Errorf("cant encode ipv6 mp reach nlri: %v\n", err)
		return
	}
	if len(encodedIPv6MPREACH) != len(encIPv6MPREACH) {
		t.Errorf("len of encoded ipv6  mp reach nlri is not equal to len of etalon\n")
		return
	}
	for i := 0; i < len(encIPv6MPREACH); i++ {
		if encIPv6MPREACH[i] != encodedIPv6MPREACH[i] {
			t.Errorf("encoded ipv6 mp reach nlri is not equal to etalon")
			return
		}
	}
	mpReachHdr, err := DecodeMP_REACH_NLRI_HDR(encIPv6MPREACH)
	if err != nil {
		t.Errorf("cant decode mp_reach_nlri hdr: %v\n", err)
		return
	}
	decIPv6MPREACHnh, decIPv6MPREACHnlri, err := DecodeIPV6_MP_REACH_NLRI(encIPv6MPREACH[FOUR_OCTETS:],
		mpReachHdr)
	if err != nil {
		t.Errorf("cant decode encoded mp_reach_nlri for ipv6: %v\n", err)
	}
	if decIPv6MPREACHnlri[0].Prefix != nlri.Prefix ||
		decIPv6MPREACHnlri[0].Length != nlri.Length ||
		decIPv6MPREACHnh != v6nh {
		fmt.Printf("%#v\n", nlri)
		fmt.Printf("%#v\n", decIPv6MPREACHnlri)
		fmt.Printf("%#v\n", v6nh)
		fmt.Printf("%#v\n", decIPv6MPREACHnh)
		t.Errorf("decoded nlri not equal to original\n")
		return
	}
}

func TestIPv6MP_UNREACH_Encoding(t *testing.T) {
	nlri := IPV6_NLRI{Length: 48}
	v6addr, _ := IPv6StringToAddr("2a00:bdc0:e003::")
	nlri.Prefix = v6addr
	encIPv6MPUNREACH, err := EncodeIPV6_MP_UNREACH_NLRI([]IPV6_NLRI{nlri})
	if err != nil {
		t.Errorf("cant encode ipv6 mp reach nlri: %v\n", err)
		return
	}
	fmt.Println(encIPv6MPUNREACH)
}

func TestIPv6MP_REACH_PathAttrEncoding(t *testing.T) {
	encodedIPv6MPREACHPA, _ := hex.DecodeString(hexIPv6_MP_REACH_NLRI_PA)
	nlri := IPV6_NLRI{Length: 48}
	v6addr, _ := IPv6StringToAddr("2a00:bdc0:e003::")
	v6nh, _ := IPv6StringToAddr("2001:7f8:20:101::245:180")
	nlri.Prefix = v6addr
	pa := PathAttr{}
	encIPv6MPREACHPA, err := EncodeV6MPRNLRI(v6nh, []IPV6_NLRI{nlri}, &pa)
	if err != nil {
		t.Errorf("cant encode ipv6 mp reach nlri: %v\n", err)
		return
	}
	if len(encodedIPv6MPREACHPA) != len(encIPv6MPREACHPA) {
		t.Errorf("len of encoded ipv6  mp reach nlri is not equal to len of etalon\n")
		return
	}
	for i := 0; i < len(encIPv6MPREACHPA); i++ {
		if encIPv6MPREACHPA[i] != encodedIPv6MPREACHPA[i] {
			fmt.Println(encodedIPv6MPREACHPA)
			fmt.Println(encIPv6MPREACHPA)
			t.Errorf("encoded ipv6 mp reach nlri is not equal to etalon")
			return
		}
	}
}

func TestIPv6MP_UNREACH_PathAttrEncoding(t *testing.T) {
	nlri := IPV6_NLRI{Length: 48}
	v6addr, _ := IPv6StringToAddr("2a00:bdc0:e003::")
	nlri.Prefix = v6addr
	pa := PathAttr{}
	encIPv6MPUNREACHPA, err := EncodeV6MPUNRNLRI([]IPV6_NLRI{nlri}, &pa)
	if err != nil {
		t.Errorf("cant encode ipv6 mp unreach nlri: %v\n", err)
		return
	}
	fmt.Println(encIPv6MPUNREACHPA)
}

func TestEncodeDecodeUpdateMsgV6(t *testing.T) {
	bgpRoute := BGPRoute{
		ORIGIN:          ORIGIN_IGP,
		MULTI_EXIT_DISC: uint32(123),
		LOCAL_PREF:      uint32(11),
		ATOMIC_AGGR:     true,
	}
	bgpRoute.NEXT_HOPv6, _ = IPv6StringToAddr("fc00::1")
	p1, _ := IPv6StringToAddr("2a02:6b8::")
	p2, _ := IPv6StringToAddr("2a00:1450:4010::")
	p3, _ := IPv6StringToAddr("2a03:2880:2130:cf05:face:b00c::1")
	bgpRoute.RoutesV6 = append(bgpRoute.RoutesV6, IPV6_NLRI{Length: 32, Prefix: p1})
	bgpRoute.RoutesV6 = append(bgpRoute.RoutesV6, IPV6_NLRI{Length: 48, Prefix: p2})
	bgpRoute.RoutesV6 = append(bgpRoute.RoutesV6, IPV6_NLRI{Length: 128, Prefix: p3})
	msg, err := EncodeUpdateMsg(&bgpRoute)
	if err != nil {
		t.Errorf("cant encode update msg with ipv6 mp_reach_nlri attr: %v\n", err)
		return
	}
	bgpRouteDec, err := DecodeUpdateMsg(msg, &BGPCapabilities{})
	if err != nil {
		t.Errorf("cant decode encoded v6 route: %v\n", err)
		return
	}
	if len(bgpRouteDec.RoutesV6) != 3 {
		t.Errorf("error in ipv6 mp_nlri decoding:wrong len\n")
		return
	}
	if bgpRouteDec.RoutesV6[0].Prefix != p1 &&
		bgpRouteDec.RoutesV6[1].Prefix != p2 &&
		bgpRouteDec.RoutesV6[2].Prefix != p3 {
		fmt.Println(bgpRouteDec.RoutesV6)
		fmt.Println(p1)
		fmt.Println(p2)
		fmt.Println(p3)
		t.Errorf("error in ipv6 mp_nlri decoding: prefix dont match\n")
		return
	}
}

func TestEncodeDecodeWithdrawUpdateMsgV6(t *testing.T) {
	var bgpRoute BGPRoute
	p1, _ := IPv6StringToAddr("2a02:6b8::")
	p2, _ := IPv6StringToAddr("2a00:1450:4010::")
	p3, _ := IPv6StringToAddr("2a03:2880:2130:cf05:face:b00c::1")
	bgpRoute.WithdrawRoutesV6 = append(bgpRoute.WithdrawRoutesV6, IPV6_NLRI{Length: 32, Prefix: p1})
	bgpRoute.WithdrawRoutesV6 = append(bgpRoute.WithdrawRoutesV6, IPV6_NLRI{Length: 48, Prefix: p2})
	bgpRoute.WithdrawRoutesV6 = append(bgpRoute.WithdrawRoutesV6, IPV6_NLRI{Length: 128, Prefix: p3})
	msg, err := EncodeUpdateMsg(&bgpRoute)
	if err != nil {
		t.Errorf("cant encode update msg with ipv6 mp_reach_nlri attr: %v\n", err)
		return
	}
	bgpRouteDec, err := DecodeUpdateMsg(msg, &BGPCapabilities{})
	if err != nil {
		t.Errorf("cant decode encoded v6 route: %v\n", err)
		return
	}
	fmt.Printf("%#v\n", bgpRouteDec)
}

/* ipv4 */

func TestIPv4NLRIEncodingDecoding(t *testing.T) {
	//encodedIPv6NLRI, _ := hex.DecodeString(hexIPv6NLRI)
	nlri := IPV4_NLRI{Length: 22}
	v4addr, err := IPv4ToUint32("10.10.252.0")
	if err != nil {
		t.Errorf("error during ipv4 addr converting: %v\n", err)
		return
	}
	nlri.Prefix = v4addr
	encIPv4NLRI, err := EncodeIPv4NLRI(RouteFlags{}, []IPV4_NLRI{nlri})
	if err != nil {
		t.Errorf("cant encode ipv4 nlri: %v\n", err)
		return
	}
	decIpv4nlri, err := DecodeIPv4NLRI(RouteFlags{}, encIPv4NLRI)
	if err != nil {
		t.Errorf("cant decode encoded nlri: %v\n", err)
		return
	}
	if decIpv4nlri[0].Length != nlri.Length && decIpv4nlri[0].Prefix != nlri.Prefix {
		fmt.Println(decIpv4nlri)
		fmt.Println(nlri)
		t.Errorf("decoded nlri not equal to original")
		return
	}
}

func TestIPv4MP_REACH_EncodingDecoding(t *testing.T) {
	//encodedIPv6MPREACH, _ := hex.DecodeString(hexIPv6_MP_REACH)
	nlri := IPV4_NLRI{Length: 22}
	v4addr, _ := IPv4ToUint32("10.10.252.0")
	v4nh, _ := IPv4ToUint32("172.16.1.1")
	nlri.Prefix = v4addr
	encIPv4MPREACH, err := EncodeIPV4_MP_REACH_NLRI(v4nh, RouteFlags{},
		[]IPV4_NLRI{nlri})
	if err != nil {
		t.Errorf("cant encode ipv4 mp reach nlri: %v\n", err)
		return
	}
	mpReachHdr, err := DecodeMP_REACH_NLRI_HDR(encIPv4MPREACH)
	if err != nil {
		t.Errorf("cant decode mp_reach_nlri hdr: %v\n", err)
		return
	}
	decIPv4MPREACHnh, decIPv4MPREACHnlri, err := DecodeIPV4_MP_REACH_NLRI(
		RouteFlags{},
		encIPv4MPREACH[FOUR_OCTETS:],
		mpReachHdr)
	if err != nil {
		t.Errorf("cant decode encoded mp_reach_nlri for ipv4: %v\n", err)
		return
	}
	if len(decIPv4MPREACHnlri) != 1 {
		t.Errorf("error in decoding of mp_reach_nlri for ipv4. nlri's length not equal to 1 in this testcase")
		return
	}
	if decIPv4MPREACHnlri[0].Prefix != nlri.Prefix ||
		decIPv4MPREACHnlri[0].Length != nlri.Length ||
		decIPv4MPREACHnh != v4nh {
		fmt.Printf("%#v\n", nlri)
		fmt.Printf("%#v\n", decIPv4MPREACHnlri)
		fmt.Printf("%#v\n", v4nh)
		fmt.Printf("%#v\n", decIPv4MPREACHnh)
		t.Errorf("decoded nlri not equal to original\n")
		return
	}
}

func TestIPv4MP_UNREACH_Encoding(t *testing.T) {
	nlri := IPV4_NLRI{Length: 22}
	v4addr, _ := IPv4ToUint32("10.10.252.0")
	nlri.Prefix = v4addr
	encIPv4MPUNREACH, err := EncodeIPV4_MP_UNREACH_NLRI(RouteFlags{},
		[]IPV4_NLRI{nlri})
	if err != nil {
		t.Errorf("cant encode ipv4 mp unreach nlri: %v\n", err)
		return
	}
	fmt.Println(encIPv4MPUNREACH)
}

func TestIPv4MP_REACH_PathAttrEncoding(t *testing.T) {
	//encodedIPv6MPREACHPA, _ := hex.DecodeString(hexIPv6_MP_REACH_NLRI_PA)
	nlri := IPV4_NLRI{Length: 22}
	v4addr, _ := IPv4ToUint32("10.10.252.0")
	v4nh, _ := IPv4ToUint32("172.16.1.1")
	nlri.Prefix = v4addr
	pa := PathAttr{}
	_, err := EncodeV4MPRNLRI(v4nh, RouteFlags{},
		[]IPV4_NLRI{nlri}, &pa)
	if err != nil {
		t.Errorf("cant encode ipv4 mp reach nlri: %v\n", err)
		return
	}
}

func TestIPv4MP_UNREACH_PathAttrEncoding(t *testing.T) {
	nlri := IPV4_NLRI{Length: 22}
	v4addr, _ := IPv4ToUint32("10.10.252.0")
	nlri.Prefix = v4addr
	pa := PathAttr{}
	encIPv4MPUNREACHPA, err := EncodeV4MPUNRNLRI(RouteFlags{},
		[]IPV4_NLRI{nlri}, &pa)
	if err != nil {
		t.Errorf("cant encode ipv4 mp unreach nlri: %v\n", err)
		return
	}
	fmt.Println(encIPv4MPUNREACHPA)
}

/* ipv4 w/ AddPath */

func TestIPv4AddPathMP_REACH_EncodingDecoding(t *testing.T) {
	//encodedIPv6MPREACH, _ := hex.DecodeString(hexIPv6_MP_REACH)
	nlri := IPV4_NLRI{Length: 22, PathID: 10}
	v4addr, _ := IPv4ToUint32("10.10.252.0")
	v4nh, _ := IPv4ToUint32("172.16.1.1")
	nlri.Prefix = v4addr
	encIPv4MPREACH, err := EncodeIPV4_MP_REACH_NLRI(v4nh, RouteFlags{WithPathId: true},
		[]IPV4_NLRI{nlri})
	if err != nil {
		t.Errorf("cant encode ipv4 mp reach nlri: %v\n", err)
		return
	}
	mpReachHdr, err := DecodeMP_REACH_NLRI_HDR(encIPv4MPREACH)
	if err != nil {
		t.Errorf("cant decode mp_reach_nlri hdr: %v\n", err)
		return
	}
	decIPv4MPREACHnh, decIPv4MPREACHnlri, err := DecodeIPV4_MP_REACH_NLRI(
		RouteFlags{WithPathId: true},
		encIPv4MPREACH[FOUR_OCTETS:],
		mpReachHdr)
	if err != nil {
		t.Errorf("cant decode encoded mp_reach_nlri for ipv4: %v\n", err)
		return
	}
	if len(decIPv4MPREACHnlri) != 1 {
		t.Errorf("error in decoding of mp_reach_nlri for ipv4. nlri's length not equal to 1 in this testcase")
		return
	}
	if decIPv4MPREACHnlri[0].Prefix != nlri.Prefix ||
		decIPv4MPREACHnlri[0].Length != nlri.Length ||
		decIPv4MPREACHnh != v4nh || decIPv4MPREACHnlri[0].PathID != nlri.PathID {
		fmt.Printf("%#v\n", nlri)
		fmt.Printf("%#v\n", decIPv4MPREACHnlri)
		fmt.Printf("%#v\n", v4nh)
		fmt.Printf("%#v\n", decIPv4MPREACHnh)
		fmt.Printf("%#v\n", decIPv4MPREACHnlri[0].PathID)
		t.Errorf("decoded nlri not equal to original\n")
		return
	}
	fmt.Printf("%#v\n", decIPv4MPREACHnlri)
}

func TestIPv4AddPathMP_UNREACH_Encoding(t *testing.T) {
	nlri := IPV4_NLRI{Length: 22, PathID: 10}
	v4addr, _ := IPv4ToUint32("10.10.252.0")
	nlri.Prefix = v4addr
	encIPv4MPUNREACH, err := EncodeIPV4_MP_UNREACH_NLRI(RouteFlags{WithPathId: true},
		[]IPV4_NLRI{nlri})
	if err != nil {
		t.Errorf("cant encode ipv4 w/ path id mp unreach nlri: %v\n", err)
		return
	}
	fmt.Println(encIPv4MPUNREACH)
}

/* ipv4 labeled unicast */

func TestIPv4LabeledMP_REACH_EncodingDecoding(t *testing.T) {
	//encodedIPv6MPREACH, _ := hex.DecodeString(hexIPv6_MP_REACH)
	nlri := IPV4_NLRI{Length: 23, Label: 1888}
	v4addr, _ := IPv4ToUint32("10.10.252.0")
	v4nh, _ := IPv4ToUint32("172.16.1.1")
	nlri.Prefix = v4addr
	encIPv4MPREACH, err := EncodeLabeledIPV4_MP_REACH_NLRI(v4nh, RouteFlags{Labeled: true},
		[]IPV4_NLRI{nlri})
	if err != nil {
		t.Errorf("cant encode ipv4 labeled mp reach nlri: %v\n", err)
		return
	}
	mpReachHdr, err := DecodeMP_REACH_NLRI_HDR(encIPv4MPREACH)
	if err != nil {
		t.Errorf("cant decode mp_reach_nlri hdr: %v\n", err)
		return
	}
	if mpReachHdr.SAFI != MP_SAFI_LABELED {
		t.Errorf("error in mp_reach_nlri labeled ipv4 hdr decoding\n")
		return
	}
	decIPv4MPREACHnh, decIPv4MPREACHnlri, err := DecodeIPV4_MP_REACH_NLRI(
		RouteFlags{Labeled: true},
		encIPv4MPREACH[FOUR_OCTETS:],
		mpReachHdr)
	if err != nil {
		t.Errorf("cant decode encoded mp_reach_nlri for labeled ipv4: %v\n", err)
		return
	}
	if len(decIPv4MPREACHnlri) != 1 {
		t.Errorf("error in decoding of mp_reach_nlri for ipv4. nlri's length not equal to 1 in this testcase")
		return
	}
	if decIPv4MPREACHnlri[0].Prefix != nlri.Prefix ||
		decIPv4MPREACHnlri[0].Length != nlri.Length ||
		decIPv4MPREACHnh != v4nh || decIPv4MPREACHnlri[0].Label != nlri.Label {
		fmt.Printf("%#v\n", nlri)
		fmt.Printf("%#v\n", decIPv4MPREACHnlri)
		fmt.Printf("%#v\n", v4nh)
		fmt.Printf("%#v\n", decIPv4MPREACHnh)
		fmt.Printf("%#v\n", decIPv4MPREACHnlri[0].Label)
		t.Errorf("decoded nlri not equal to original\n")
		return
	}
	fmt.Printf("%#v\n", decIPv4MPREACHnlri)
}

func TestIPv4LabeledMP_UNREACH_Encoding(t *testing.T) {
	nlri := IPV4_NLRI{Length: 22, Label: 1888}
	v4addr, _ := IPv4ToUint32("10.10.252.0")
	nlri.Prefix = v4addr
	encIPv4MPUNREACH, err := EncodeLabeledIPV4_MP_UNREACH_NLRI(RouteFlags{Labeled: true},
		[]IPV4_NLRI{nlri})
	if err != nil {
		t.Errorf("cant encode labled ipv4 mp unreach nlri: %v\n", err)
		return
	}
	fmt.Println(encIPv4MPUNREACH)
}

/* ipv4 labeled unicast  w/ 6 routes and communities generated at  Juniper */
func TestIPv4LabeledDecodeUpdate(t *testing.T) {
	encodedUpdate, _ := hex.DecodeString(hexLabeledIPv4_MP_REACH_NLRI)
	bgpRoute, err := DecodeUpdateMsg(encodedUpdate, &BGPCapabilities{SupportASN4: true})
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during update  msg decoding")
		return
	}
	fmt.Println("###### decoded labeled IPv4 #####")
	fmt.Printf("%#v\n", bgpRoute)
	PrintBgpUpdate(&bgpRoute)
}

//Benchmarking

func BenchmarkDecodeUpdMsgWithAsPath(b *testing.B) {
	encodedUpdate, _ := hex.DecodeString(hexUpdate4)
	caps := BGPCapabilities{}
	caps.SupportASN4 = true
	for i := 1; i < b.N; i++ {
		DecodeUpdateMsg(encodedUpdate, &caps)
	}
	//PrintBgpUpdate(&bgpRoute)
}

func BenchmarkEncodeUpdateMsg1(b *testing.B) {
	bgpRoute := BGPRoute{
		ORIGIN:          ORIGIN_IGP,
		MULTI_EXIT_DISC: uint32(123),
		LOCAL_PREF:      uint32(11),
		ATOMIC_AGGR:     true,
	}
	p1, _ := IPv4ToUint32("1.92.0.0")
	p2, _ := IPv4ToUint32("11.92.128.0")
	p3, _ := IPv4ToUint32("1.1.1.10")
	bgpRoute.Routes = append(bgpRoute.Routes, IPV4_NLRI{Length: 12, Prefix: p1})
	bgpRoute.Routes = append(bgpRoute.Routes, IPV4_NLRI{Length: 22, Prefix: p2})
	bgpRoute.Routes = append(bgpRoute.Routes, IPV4_NLRI{Length: 32, Prefix: p3})
	bgpRoute.AddV4NextHop("10.0.0.2")
	for i := 0; i < b.N; i++ {
		EncodeUpdateMsg(&bgpRoute)
	}
}

func BenchmarkEncodeUpdateMsgMPINET(b *testing.B) {
	bgpRoute := BGPRoute{
		ORIGIN:          ORIGIN_IGP,
		MULTI_EXIT_DISC: uint32(123),
		LOCAL_PREF:      uint32(11),
		ATOMIC_AGGR:     true,
	}
	p1, _ := IPv4ToUint32("1.92.0.0")
	p2, _ := IPv4ToUint32("11.92.128.0")
	p3, _ := IPv4ToUint32("1.1.1.10")
	bgpRoute.Routes = append(bgpRoute.Routes, IPV4_NLRI{Length: 12, Prefix: p1})
	bgpRoute.Routes = append(bgpRoute.Routes, IPV4_NLRI{Length: 22, Prefix: p2})
	bgpRoute.Routes = append(bgpRoute.Routes, IPV4_NLRI{Length: 32, Prefix: p3})
	bgpRoute.NEXT_HOPv4, _ = IPv4ToUint32("10.0.0.2")
	bgpRoute.MPINET = true
	for i := 0; i < b.N; i++ {
		EncodeUpdateMsg(&bgpRoute)
	}
}

func BenchmarkEncodeUpdateMsgV6(b *testing.B) {
	bgpRoute := BGPRoute{
		ORIGIN:          ORIGIN_IGP,
		MULTI_EXIT_DISC: uint32(123),
		LOCAL_PREF:      uint32(11),
		ATOMIC_AGGR:     true,
	}
	bgpRoute.NEXT_HOPv6, _ = IPv6StringToAddr("fc00::1")
	p1, _ := IPv6StringToAddr("2a02:6b8::")
	p2, _ := IPv6StringToAddr("2a00:1450:4010::")
	p3, _ := IPv6StringToAddr("2a03:2880:2130:cf05:face:b00c::1")
	bgpRoute.RoutesV6 = append(bgpRoute.RoutesV6, IPV6_NLRI{Length: 32, Prefix: p1})
	bgpRoute.RoutesV6 = append(bgpRoute.RoutesV6, IPV6_NLRI{Length: 48, Prefix: p2})
	bgpRoute.RoutesV6 = append(bgpRoute.RoutesV6, IPV6_NLRI{Length: 128, Prefix: p3})
	for i := 0; i < b.N; i++ {
		EncodeUpdateMsg(&bgpRoute)
	}
}

func BenchmarkEncodeOpen(b *testing.B) {
	capList := []MPCapability{
		MPCapability{AFI: MP_AFI_IPV4, SAFI: MP_SAFI_UCAST},
		MPCapability{AFI: MP_AFI_IPV6, SAFI: MP_SAFI_UCAST}}
	openMsg := OpenMsg{Hdr: OpenMsgHdr{Version: 4, MyASN: 65000, HoldTime: 90, BGPID: 167772162}}
	openMsg.MPCaps = append(openMsg.MPCaps, capList...)
	for i := 0; i < b.N; i++ {
		EncodeOpenMsg(&openMsg)
	}
}

func BenchmarkDecodeOpen(b *testing.B) {
	capList := []MPCapability{
		MPCapability{AFI: MP_AFI_IPV4, SAFI: MP_SAFI_UCAST},
		MPCapability{AFI: MP_AFI_IPV6, SAFI: MP_SAFI_UCAST}}
	openMsg := OpenMsg{Hdr: OpenMsgHdr{Version: 4, MyASN: 65000, HoldTime: 90, BGPID: 167772162}}
	openMsg.MPCaps = append(openMsg.MPCaps, capList...)
	data, _ := EncodeOpenMsg(&openMsg)
	for i := 0; i < b.N; i++ {
		DecodeOpenMsg(data[MSG_HDR_SIZE:])
	}
}
