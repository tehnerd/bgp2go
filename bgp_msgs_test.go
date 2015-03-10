package bgp

import (
	"encoding/hex"
	"fmt"
	"testing"
)

const (
	hexOpenMsg = "ffffffffffffffffffffffffffffffff003b0104fde8005a0a0000021e02060104000100010202800002020200020440020078020641040000fde8"
	hexUpdate1 = "ffffffffffffffffffffffffffffffff00360200000015400101004002004003040a0000024005040000006420010101012001010102"
	hexUpdate2 = "ffffffffffffffffffffffffffffffff00170200000000"
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
	updateMsg, err := DecodeUpdateMsg(encodedUpdate[19:])
	if err != nil {
		fmt.Println(err)
		t.Errorf("error during update  msg decoding")
	}
	fmt.Println(updateMsg)
}
