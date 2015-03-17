package bgp

import (
	"encoding/hex"
	"fmt"
	"testing"
)

const (
	hexOpenMsg      = "ffffffffffffffffffffffffffffffff003b0104fde8005a0a0000021e02060104000100010202800002020200020440020078020641040000fde8"
	hexUpdate1      = "ffffffffffffffffffffffffffffffff00360200000015400101004002004003040a0000024005040000006420010101012001010102"
	hexUpdate2      = "ffffffffffffffffffffffffffffffff0038020000001c400101004002004003040a00000280040400000078400504000000642001010103"
	hexUpdate3      = "ffffffffffffffffffffffffffffffff00170200000000"
	hexUpdate4      = "ffffffffffffffffffffffffffffffff005102000000364001010240021a02060000000100000002000000030000000400000005000000064003040a00000240050400000064c00804ffff000118010b01"
	hexKA           = "ffffffffffffffffffffffffffffffff001304"
	hexNotification = "ffffffffffffffffffffffffffffffff0015030607"
)

func TestDecodeMsgHeader(t *testing.T) {
	encodedOpen, _ := hex.DecodeString(hexOpenMsg)
	msgHdr, err := DecodeMsgHeader(encodedOpen)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during bgp msg header decoding")
	}
	fmt.Printf("%v %v %v\n", msgHdr.Marker, msgHdr.Length, msgHdr.Type)
}

func TestEncodeMsgHeader(t *testing.T) {
	encodedOpen, _ := hex.DecodeString(hexOpenMsg)
	msgHdr := MsgHeader{Length: 59, Type: 1}
	encMsgHdr, err := EncodeMsgHeader(&msgHdr)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during bgp msg header encoding")
	}
	if len(encMsgHdr) != 19 {
		fmt.Println(len(encMsgHdr))
		fmt.Println(encMsgHdr)
		t.Errorf("error in len of encoded hdr")
	}
	for cntr := 0; cntr < len(encMsgHdr); cntr++ {
		if encMsgHdr[cntr] != encodedOpen[cntr] {
			t.Errorf("byte of encoded msg is not equal to etalon's msg")
		}
	}
}

func TestDecodeOpenMsg(t *testing.T) {
	encodedOpen, _ := hex.DecodeString(hexOpenMsg)
	openMsg, err := DecodeOpenMsg(encodedOpen[19:])
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during open msg decoding")
	}
	fmt.Println(openMsg)
	fmt.Println(len(encodedOpen))
	offsetPntr := 29 //MsgHdr+OpenMsg length
	for offsetPntr < int(openMsg.OptParamLength)+29 {
		optParamHdr, err := DecodeOptionalParamHeader(encodedOpen[offsetPntr:])
		if err != nil {
			fmt.Println(err)
			t.Errorf("error during optional msg decoding")
		}
		fmt.Println(optParamHdr)
		fmt.Println(encodedOpen[offsetPntr+2 : offsetPntr+2+int(optParamHdr.ParamLength)])
		offsetPntr += (int(optParamHdr.ParamLength) + 2)
	}
}

func TestEncodeOpenMsg(t *testing.T) {
	encodedOpen, _ := hex.DecodeString(hexOpenMsg)
	openMsg := OpenMsg{Version: 4, MyASN: 65000, HoldTime: 90, BGPID: 167772162, OptParamLength: 30}
	encOpenMsg, err := EncodeOpenMsg(&openMsg)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during open msg  encoding")
	}
	for cntr := 19; cntr < len(encOpenMsg); cntr++ {
		if encOpenMsg[cntr] != encodedOpen[cntr] {
			t.Errorf("byte of encoded msg is not equal to etalon's msg")
		}
	}
}

func TestDecodeUpdateMsg(t *testing.T) {
	encodedUpdate, _ := hex.DecodeString(hexUpdate1)
	bgpRoute, err := DecodeUpdateMsg(encodedUpdate)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during update  msg decoding")
	}
	PrintBgpUpdate(&bgpRoute)
	encodedUpdate, _ = hex.DecodeString(hexUpdate2)
	bgpRoute, err = DecodeUpdateMsg(encodedUpdate)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during update  msg decoding")
	}
	PrintBgpUpdate(&bgpRoute)
}

/*
   this test fails right now coz we dont support 32bit asn yet
   bogus in as_path part; should be 1 2 3 4 5 6
*/

func TestDecodeUpdMsgWithAsPath(t *testing.T) {
	encodedUpdate, _ := hex.DecodeString(hexUpdate4)
	bgpRoute, err := DecodeUpdateMsg(encodedUpdate)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during update  msg decoding")
	}
	PrintBgpUpdate(&bgpRoute)

}

func TestEncodeKeepaliveMsg(t *testing.T) {
	encodedKA, _ := hex.DecodeString(hexKA)
	encKA := GenerateKeepalive()
	for cntr := 0; cntr < len(encKA); cntr++ {
		if encKA[cntr] != encodedKA[cntr] {
			t.Errorf("byte of encoded msg is not equal to etalon's msg")
		}
	}
}

func TestDecodeNotificationMsg(t *testing.T) {
	encodedNotification, _ := hex.DecodeString(hexNotification)
	notification, err := DecodeNotificationMsg(encodedNotification)
	if err != nil {
		t.Errorf("error during notification decoding")
	}
	fmt.Println(notification)
	if notification.ErrorCode != 6 && notification.ErrorSubcode != 7 {
		t.Errorf("error during notification decoding(code and subcode are not equal to etalon)")
	}
}

func TestEncodeNotificationMsg(t *testing.T) {
	encodedNotification, _ := hex.DecodeString(hexNotification)
	notification := NotificationMsg{ErrorCode: BGP_CASE_ERROR, ErrorSubcode: BGP_CASE_ERROR_COLLISION}
	encNotification, err := EncodeNotificationMsg(&notification)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during notification encoding")
	}
	for cntr := 0; cntr < len(encNotification); cntr++ {
		if encNotification[cntr] != encodedNotification[cntr] {
			t.Errorf("byte of encoded msg is not equal to etalon's msg")
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
	p4, _ := IPv4ToUint32("192.168.0.0")
	bgpRoute.Routes = append(bgpRoute.Routes, IPV4_NLRI{Length: 12, Prefix: p1})
	bgpRoute.Routes = append(bgpRoute.Routes, IPV4_NLRI{Length: 22, Prefix: p2})
	bgpRoute.Routes = append(bgpRoute.Routes, IPV4_NLRI{Length: 32, Prefix: p3})
	bgpRoute.WithdrawRoutes = append(bgpRoute.WithdrawRoutes, IPV4_NLRI{Length: 16, Prefix: p4})
	err := bgpRoute.AddV4NextHop("10.0.0.2")
	if err != nil {
		fmt.Println(err)
		t.Errorf("cant encode update msg")
	}
	data, err := EncodeUpdateMsg(&bgpRoute)
	if err != nil {
		fmt.Println(err)
		t.Errorf("cant encode update msg")
	}
	bgpRoute2, err := DecodeUpdateMsg(data)
	if err != nil {
		fmt.Println(err)
		t.Errorf("cant decode encoded update")
	}
	data2, _ := EncodeUpdateMsg(&bgpRoute2)
	if len(data) != len(data2) {
		t.Errorf("error in encoding/decoding of the same msg")
	}
	for cntr := 0; cntr < len(data); cntr++ {
		if data[cntr] != data2[cntr] {
			t.Errorf("error in encoding/decoding of the same msg")
			break
		}
	}
	fmt.Println(len(data))
	fmt.Println(bgpRoute)
	fmt.Println("########################")
	fmt.Println(bgpRoute2)
	PrintBgpUpdate(&bgpRoute2)
	ipv4, _ := DecodeV4NextHop(&bgpRoute2)
	fmt.Println(Uint32IPv4ToString(ipv4))
}

func TestEncodeEndOfRIB(t *testing.T) {
	eor := GenerateEndOfRIB()
	if len(eor) != 23 {
		fmt.Println(eor)
		t.Errorf("error during EndOfRib marker generation")
	}
}
