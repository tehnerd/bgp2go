package bgp2go

import (
	"fmt"
	"testing"
)

func prepareConnectionPassive() (SockControlChans, chan BGPCommand, chan BGPCommand) {
	scc := SockControlChans{}
	scc.Init()
	scc.localAddr = "192.168.0.2"
	cmndChanTo := make(chan BGPCommand)
	cmndChanFrom := make(chan BGPCommand)
	rid, _ := IPv4ToUint32("172.16.0.1")
	bgpNeighbourContext := BGPNeighbourContext{RouterID: rid,
		ASN: 6500, ToMainContext: cmndChanTo,
		ToNeighbourContext: cmndChanFrom,
		NeighbourAddr:      "192.168.0.1"}
	go StartBGPNeighbourContext(&bgpNeighbourContext, true, scc)
	return scc, cmndChanTo, cmndChanFrom
}

func generateTestNeighbourContext() BGPNeighbourContext {
	rid, _ := IPv4ToUint32("172.16.0.2")
	testContext := BGPNeighbourContext{RouterID: rid,
		ASN: 6501, ToMainContext: nil,
		ToNeighbourContext: nil,
		NeighbourAddr:      "192.168.0.2"}
	return testContext

}

func TestSessionInit(t *testing.T) {
	fmt.Println("############## SimpleBgpInjector's tests ##############")
	testContext := generateTestNeighbourContext()
	scc, fromN, toN := prepareConnectionPassive()
	//fsm: passive waits for open
	GenerateOpenMsg(&testContext, scc.readChan, "")
	//collision check
	msgFromN := <-fromN
	if msgFromN.Cmnd != "PassiveCollisionCheck" {
		fmt.Println("###")
		fmt.Println(msgFromN.Cmnd)
		t.Errorf("error in passive connection fsm. no collision check")
	}
	toN <- BGPCommand{Cmnd: "NoCollision"}
	//passive send open, and then keepalive in response to our open msg
	msg := <-scc.writeChan
	hdr, err := DecodeMsgHeader(msg)
	if err != nil {
		t.Errorf("%v\n", err)
	}
	if hdr.Type != BGP_OPEN_MSG {
		t.Errorf("wrong first msg from passive peer")
	}
	_, err = DecodeOpenMsg(msg[MSG_HDR_SIZE:])
	if err != nil {
		t.Errorf("error in parsing open msg from passive: %v\n", err)
	}
	msg = <-scc.writeChan
	hdr, err = DecodeMsgHeader(msg)
	if err != nil {
		t.Errorf("%v\n", err)
	}
	if hdr.Type != BGP_KEEPALIVE_MSG {
		t.Errorf("error in passive fsm; 2nd msg must be keepalive")
	}
	scc.readChan <- GenerateKeepalive()
	msgFromN = <-fromN
	if msgFromN.Cmnd != "PassiveEstablished" {
		t.Errorf("error in passive fsm. must be in PassiveEstablished state")
	}
}
