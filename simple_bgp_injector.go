package bgp

/*
   simple bgp injector. main purpose is to inject/withdraw
   routes into/from bgp domain (for example in any slb's
   keepalive daemons)
*/
//TODO: logging everywhere

import (
	"fmt"
	"strconv"
	"time"
)

/*
   Generic per bgp process data
*/
type BGPContext struct {
	ASN      uint32
	RouterID uint32
	//TODO: rib per afi/safi
	Rib           RIBv4
	Neighbours    []BGPNeighbour
	ToMainContext chan BGPCommand
}

/*
 IPv4 RIB
*/
type RIBv4 struct {
	Routes []BGPRoute
}

/*
 Struct, which contains all metadata about the neighbour
*/
type BGPNeighbour struct {
	Address  string
	State    string
	CmndChan chan BGPCommand
	//afi & safi, which can be sended to neighbour
	AFIs []string
}

type BGPCommand struct {
	From     string
	Cmnd     string
	CmndData string
	Route    BGPRoute
}

type BGPNeighbourContext struct {
	ToMainContext      chan BGPCommand
	ToNeighbourContext chan BGPCommand
	NeighbourAddr      string
	ASN                uint32
	RouterID           uint32
	NextHop            string
	fsm                FSM
	//placeholders, not yet implemented
	InboundPolicy  string
	OutboundPolicy string
}

/*
used to communicate w/ main bgp process from external apps.
For example:
Cmnd: Advertise
Data: ipv4/ipv6 address/mask
or
Cmnd: Withdraw
Data: ipv4/ipv6 address/mask
*/
type BGPProcessMsg struct {
	Cmnd string
	Data string
}

func StartBGPProcess(toBGPProcess, fromBGPProcess chan BGPProcessMsg,
	bgpContext BGPContext) {
	bgpContext.ToMainContext = make(chan BGPCommand)
	loop := 1
	for loop == 1 {
		select {
		case cmndToBGPProcess := <-toBGPProcess:
			(&bgpContext).ProcessExternalCommand(cmndToBGPProcess, fromBGPProcess)
		case cmndFromNeighbourContext := <-bgpContext.ToMainContext:
			(&bgpContext).ProcessNeighbourCommand(cmndFromNeighbourContext)
		}
	}

}

func (context *BGPContext) ProcessExternalCommand(cmnd BGPProcessMsg,
	responseChan chan BGPProcessMsg) {
	switch cmnd.Cmnd {
	case "AddNeighbour":
		context.AddNeighbour(cmnd.Data)
	}
}

func (context *BGPContext) ProcessNeighbourCommand(cmnd BGPCommand) {
	switch cmnd.Cmnd {
	case "NewRouterID":
		if context.RouterID == 0 {
			rid, err := IPv4ToUint32(cmnd.CmndData)
			if err != nil {
				return
			}
			context.RouterID = rid
		}
	case "GetRouterID":
		neighbour, err := context.FindNeighbour(cmnd.From)
		if err != nil {
			return
		}
		neighbour.CmndChan <- BGPCommand{Cmnd: "RouterID",
			CmndData: strconv.FormatUint(uint64(context.RouterID), 10)}
	}
}

func (context *BGPContext) FindNeighbour(neighbour string) (BGPNeighbour, error) {
	for _, existingNeighbour := range context.Neighbours {
		if existingNeighbour.Address == neighbour {
			return existingNeighbour, nil
		}
	}
	return BGPNeighbour{}, fmt.Errorf("Neighbour doesnt exists")
}

func (context *BGPContext) AddNeighbour(neighbour string) {
	_, err := context.FindNeighbour(neighbour)
	if err == nil {
		//neighbour already exists
		return
	}
	/*
	   TODO: add neighbour address parsing and/or capability lists
	   for example we could has data in format <address> <capabilities...>
	   or we could check if re match for v6 address and adds v6 capability(not flexible enough,
	   but easier to implement, and will works for slb application
	*/
	cmndChan := make(chan BGPCommand, 1)
	context.Neighbours = append(context.Neighbours, BGPNeighbour{Address: neighbour,
		State: "Idle", CmndChan: cmndChan})
	bgpNeighbourContext := BGPNeighbourContext{RouterID: context.RouterID,
		ASN: context.ASN, ToMainContext: context.ToMainContext,
		ToNeighbourContext: cmndChan, NeighbourAddr: neighbour}
	go StartBGPNeighbourContext(&bgpNeighbourContext)
}

func GetRouterID(fromConnect chan string, toMainContext chan BGPCommand) {
	//TODO: error handling
	ladr := <-fromConnect
	fmt.Println(ladr)
	toMainContext <- BGPCommand{Cmnd: "NewRouterID", CmndData: ladr}
	//TODO: send ladr to context (so it could be used as next_hop)
}

func StartBGPNeighbourContext(context *BGPNeighbourContext) {
	context.fsm.State = "Idle"
	fromWriteError := make(chan uint8)
	toWriteError := make(chan uint8)
	readError := make(chan uint8)
	readChan := make(chan []byte)
	writeChan := make(chan []byte)
	controlChan := make(chan string)
	keepaliveFeedback := make(chan uint8)
	msgBuf := make([]byte, 0)
	context.fsm.Event("Start")
	context.fsm.KeepaliveTime = 30
RECONNECT:
	go GetRouterID(controlChan, context.ToMainContext)
	err := ConnectToNeighbour(context.NeighbourAddr,
		fromWriteError, toWriteError, readError,
		readChan, writeChan, controlChan)

	if err != nil {
		if err == CANT_CONNECT_ERROR {
			context.fsm.ConnectRetryCounter++
			//TODO: fsm.ConnectionRetryTime
			time.Sleep(10 * time.Second)
			goto RECONNECT
		} else {
			/*
			   TODO: that means we wasnt able to parse neighbours address.
			   we need to inform about it main context and delete this neigbour  from the list
			*/
			return
		}
	}

	loop := 1
	if context.RouterID == 0 {
		for loop == 1 {
			context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
				Cmnd: "GetRouterID"}
			resp := <-context.ToNeighbourContext

			switch resp.Cmnd {
			case "RouterID":
				if resp.CmndData != "0" {
					fmt.Print(resp.CmndData)
					loop = 0
					id, _ := strconv.ParseUint(resp.CmndData, 10, 32)
					context.RouterID = uint32(id)
				} else {
					time.Sleep(1 * time.Second)
				}
			}
		}
	}
	//HACK; FOR POC; GONNA REMOVE IT
	GenerateOpenMsg(context, writeChan)

	loop = 1
	for loop == 1 {
		select {
		case bgpMsg := <-readChan:
			msgBuf = append(msgBuf, bgpMsg...)
			if len(msgBuf) < MSG_HDR_SIZE {
				continue
			}
			hdr, err := DecodeMsgHeader(msgBuf)
			if err != nil {
				//TODO: notification, close socket, etc
				context.fsm.Event("MsgHeaderError")
				goto RECONNECT
			}
			if len(msgBuf) < int(hdr.Length) {
				continue
			}
			switch hdr.Type {
			case BGP_OPEN_MSG:
				openMsg, err := DecodeOpenMsg(msgBuf[:hdr.Length])
				if err != nil {
					context.fsm.Event("OpenError")
					//TODO: notification, close socket, etc
					goto RECONNECT
				}
				state := context.fsm.Event("OpenRcv")
				switch state {
				case "OpenKA":
					//building open reply
					if context.ASN != 0 {
						//TODO: 32bit asn
						openMsg.MyASN = uint16(context.ASN)
					} else {
						//Hack for ibgp to work w/o any prior configuration
						context.ASN = uint32(openMsg.MyASN)
					}
					context.fsm.KeepaliveTime = uint32(openMsg.HoldTime / 3)
					openMsg.BGPID = context.RouterID
					encodedOpen, err := EncodeOpenMsg(&openMsg)
					if err != nil {
						context.fsm.Event("OpenSendError")
						//TODO:
						goto RECONNECT
					}
					encodedKA := GenerateKeepalive()
					writeChan <- encodedOpen
					writeChan <- encodedKA
				case "Keepalive":
					encodedKA := GenerateKeepalive()
					writeChan <- encodedKA
				default:
					//TODO; same as above
					goto RECONNECT
				}
			case BGP_UPDATE_MSG:
				updMsg, err := DecodeUpdateMsg(msgBuf[:hdr.Length])
				if err != nil {
					context.fsm.Event("UpdateError")
					//TODO:
					goto RECONNECT
				}
				state := context.fsm.Event("Update")
				if state != "Established" {
					goto RECONNECT
				}
				PrintBgpUpdate(&updMsg)
			case BGP_NOTIFICATION_MSG:
				context.fsm.Event("Notification")
				fmt.Println("notification")
			case BGP_KEEPALIVE_MSG:
				state := context.fsm.Event("Keepalive")
				if state == "Established" {
					go SendKeepalive(writeChan, context.fsm.KeepaliveTime,
						keepaliveFeedback)
					fmt.Println("Established")
				}
			}
			msgBuf = msgBuf[hdr.Length:]
		}
	}
}

func SendKeepalive(writeChan chan []byte, sleepTime uint32, feedbackChan chan uint8) {
	loop := 1
	ka := GenerateKeepalive()
	for loop == 1 {
		time.Sleep(time.Duration(sleepTime) * time.Second)
		select {
		case writeChan <- ka:
			continue
		case <-feedbackChan:
			loop = 0
			continue
		}
	}
}

func GenerateOpenMsg(context *BGPNeighbourContext, writeChan chan []byte) {
	openMsg := OpenMsg{Version: uint8(4), MyASN: uint16(context.ASN),
		BGPID: context.RouterID, HoldTime: uint16(90)}
	encodedOpen, err := EncodeOpenMsg(&openMsg)
	if err != nil {
		return
	}
	writeChan <- encodedOpen
	context.fsm.Event("OpenSent")
}
