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
	"strings"
	"time"
)

/*
   Generic per bgp process data
*/
type BGPContext struct {
	ASN      uint32
	RouterID uint32
	//TODO: rib per afi/safi
	RIBv4         []IPV4_NLRI
	ListenLocal   bool
	Neighbours    []BGPNeighbour
	ToMainContext chan BGPCommand
}

/*
 Struct, which contains all metadata about the neighbour
*/
type BGPNeighbour struct {
	Address                   string
	State                     string
	CmndChan                  chan BGPCommand
	toPassiveNeighbourContext chan BGPCommand
	//afi & safi, which can be sended to neighbour
	AFIs []string
	//for active/passive collision detection
	passiveExist    bool
	activeConnected bool
}

type BGPCommand struct {
	From     string
	Cmnd     string
	CmndData string
	Route    BGPRoute
	//For anonymous connections
	ResponseChan chan string
	//for passive(when someone connected to us) connection to start
	sockChans SockControlChans
}

type BGPNeighbourContext struct {
	ToMainContext      chan BGPCommand
	ToNeighbourContext chan BGPCommand
	/*
	   used when we have both inboud and outbound coonnection to the same
	   peer and yet do not know which one is going to be threated as collision
	*/
	NeighbourAddr string
	ASN           uint32
	RouterID      uint32
	NextHop       string
	fsm           FSM
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
	//we need root access to bind @ < 1024 port
	if bgpContext.ListenLocal {
		go BGPListenForConnection(bgpContext.ToMainContext)
	}
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
	case "AddV4Route":
		context.AddV4Route(cmnd.Data)
	case "WithdrawV4Route":
		context.WithdrawV4Route(cmnd.Data)
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

	case "NewConnection":
		neighbour, err := context.FindNeighbour(cmnd.CmndData)
		if err != nil {
			cmnd.ResponseChan <- "teardown"
			return
		}
		if neighbour.State == "Established" {
			cmnd.ResponseChan <- "teardown"
			return
		}
		cmnd.ResponseChan <- "continue"
		return

	case "GetRouterID":
		neighbour, err := context.FindNeighbour(cmnd.From)
		if err != nil {
			return
		}
		neighbour.CmndChan <- BGPCommand{Cmnd: "RouterID",
			CmndData: strconv.FormatUint(uint64(context.RouterID), 10)}

	case "GetRouterIDPassive":
		neighbour, err := context.FindNeighbour(cmnd.From)
		if err != nil {
			return
		}
		neighbour.toPassiveNeighbourContext <- BGPCommand{Cmnd: "RouterID",
			CmndData: strconv.FormatUint(uint64(context.RouterID), 10)}

	case "AddPassiveNeighbour":
		context.AddPassiveNeighbour(cmnd.CmndData, cmnd.sockChans)

	case "PassiveCollisionCheck":
		context.ShouldCheckCollision(cmnd.From, true)

	case "CollisionCheck":
		context.ShouldCheckCollision(cmnd.From, false)

	case "PassiveWonCollisionDetection", "PassiveClossed", "ActiveClossed",
		"ActiveConnected", "Down", "Established", "PassiveEstablished":
		context.ChangeNeighbourInfo(cmnd.From, cmnd.Cmnd)

	case "PassiveTeardown":
		context.RestartActiveNeighbour(cmnd.From)

	case "ActiveStartConnection":
		context.CheckNeighbourInfo(&cmnd)
	}
}

func (context *BGPContext) FindNeighbour(neighbour string) (*BGPNeighbour, error) {
	for i, existingNeighbour := range context.Neighbours {
		if existingNeighbour.Address == neighbour {
			return &context.Neighbours[i], nil
		}
	}
	return nil, fmt.Errorf("Neighbour doesnt exists")
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
	passiveCmndChan := make(chan BGPCommand, 1)
	context.Neighbours = append(context.Neighbours, BGPNeighbour{
		Address: neighbour,
		State:   "Idle", CmndChan: cmndChan,
		toPassiveNeighbourContext: passiveCmndChan})
	bgpNeighbourContext := BGPNeighbourContext{RouterID: context.RouterID,
		ASN: context.ASN, ToMainContext: context.ToMainContext,
		ToNeighbourContext: cmndChan,
		NeighbourAddr:      neighbour}
	go StartBGPNeighbourContext(&bgpNeighbourContext, false, SockControlChans{})
}

func (context *BGPContext) RestartActiveNeighbour(neighbour string) {
	bgpNeighbour, err := context.FindNeighbour(neighbour)
	if err != nil {
		/*
		   should never fails, coz we restarts already existing neighbour context
		*/
		return
	}
	if bgpNeighbour.CmndChan == bgpNeighbour.toPassiveNeighbourContext {
		cmndChan := make(chan BGPCommand, 1)
		bgpNeighbour.CmndChan = cmndChan
	}
	bgpNeighbourContext := BGPNeighbourContext{RouterID: context.RouterID,
		ASN: context.ASN, ToMainContext: context.ToMainContext,
		ToNeighbourContext: bgpNeighbour.CmndChan,
		NeighbourAddr:      neighbour}

	go StartBGPNeighbourContext(&bgpNeighbourContext, false, SockControlChans{})

}

func (context *BGPContext) AddPassiveNeighbour(neighbourAddr string, sockChans SockControlChans) {
	neighbour, err := context.FindNeighbour(neighbourAddr)
	if err != nil {
		/*
		   FIXME: possible leak; this is very unlikely situation
		   when we have passed FindNeighbour test during "NewConnection" phase;
		   but somehow after that neighbour was deleted. in this situation proper
		   actions would be  to close sockets etc (we can send cmnds to chans from
		   SockControllChans struct)
		*/
		return
	}
	neighbour.passiveExist = true
	bgpNeighbourContext := BGPNeighbourContext{RouterID: context.RouterID,
		ASN: context.ASN, ToMainContext: context.ToMainContext,
		ToNeighbourContext: neighbour.toPassiveNeighbourContext,
		NeighbourAddr:      neighbourAddr}
	go StartBGPNeighbourContext(&bgpNeighbourContext, true, sockChans)
}

func (context *BGPContext) ShouldCheckCollision(neighbourAddr string, passive bool) {
	neighbour, err := context.FindNeighbour(neighbourAddr)
	if err != nil {
		//TODO: proper handling
		return
	}
	bgpCmnd := BGPCommand{}
	if passive {
		if neighbour.State != "Established" && neighbour.activeConnected == true {
			bgpCmnd.Cmnd = "PerformCollisionCheck"
		} else {
			bgpCmnd.Cmnd = "NoCollision"
		}
		neighbour.toPassiveNeighbourContext <- bgpCmnd
		return
	} else {
		if neighbour.State != "Established" && neighbour.passiveExist == true {
			bgpCmnd.Cmnd = "PerformCollisionCheck"
		} else {
			bgpCmnd.Cmnd = "NoCollision"
		}
		neighbour.CmndChan <- bgpCmnd
	}
}

func (context *BGPContext) ChangeNeighbourInfo(neighbourAddr string, cmnd string) {
	neighbour, err := context.FindNeighbour(neighbourAddr)
	if err != nil {
		//TODO: proper handling
		return
	}

	switch cmnd {
	case "PassiveWonCollisionDetection":
		neighbour.CmndChan = neighbour.toPassiveNeighbourContext
	case "PassiveClossed":
		neighbour.passiveExist = false
	case "ActiveClossed":
		neighbour.activeConnected = false
	case "ActiveConnected":
		neighbour.activeConnected = true
	case "Established":
		neighbour.State = "Established"
		context.AdvertiseAllRoutesV4(neighbour.CmndChan)
	case "PassiveEstablished":
		neighbour.State = "Established"
		neighbour.CmndChan = neighbour.toPassiveNeighbourContext
		context.AdvertiseAllRoutesV4(neighbour.CmndChan)
	case "Down":
		neighbour.State = "Down"
	}

}

func (context *BGPContext) CheckNeighbourInfo(cmnd *BGPCommand) {
	neighbour, err := context.FindNeighbour(cmnd.From)
	if err != nil {
		return
	}
	switch cmnd.Cmnd {
	case "ActiveStartConnection":
		if neighbour.State == "Established" {
			cmnd.ResponseChan <- "teardown"
		} else {
			cmnd.ResponseChan <- "continue"
		}
	}
}

func (context *BGPContext) AddV4Route(route string) {
	//TODO:check/parse route
	splittedRoute := strings.Split(route, "/")
	if len(splittedRoute) != 2 {
		return
	}
	val, err := strconv.ParseUint(splittedRoute[1], 10, 8)
	if err != nil {
		return
	}
	mask := uint8(val)
	ipv4, err := IPv4ToUint32(splittedRoute[0])
	if err != nil {
		return
	}

	_, err = context.FindV4Route(ipv4, mask)
	if err == nil {
		//this means that route already exists
		return
	}

	newRoute := IPV4_NLRI{Length: mask, Prefix: ipv4}
	context.RIBv4 = append(context.RIBv4, newRoute)
	context.AdvertiseRouteV4(newRoute)

}

func (context *BGPContext) WithdrawV4Route(route string) {
	//TODO:check/parse route
	splittedRoute := strings.Split(route, "/")
	if len(splittedRoute) != 2 {
		return
	}
	val, err := strconv.ParseUint(splittedRoute[1], 10, 8)
	if err != nil {
		return
	}
	mask := uint8(val)
	ipv4, err := IPv4ToUint32(splittedRoute[0])
	if err != nil {
		return
	}

	err = context.DeleteV4Route(ipv4, mask)
	if err != nil {
		//this means that route doesnt exists
		return
	}

	wRoute := IPV4_NLRI{Length: mask, Prefix: ipv4}
	context.WithdrawRouteV4(wRoute)

}

func (context *BGPContext) FindV4Route(ipv4 uint32, mask uint8) (IPV4_NLRI, error) {
	for _, nlri := range context.RIBv4 {
		if nlri.Prefix == ipv4 && nlri.Length == mask {
			return nlri, nil
		}
	}
	return IPV4_NLRI{}, fmt.Errorf("route doesnt exists")
}

func (context *BGPContext) DeleteV4Route(ipv4 uint32, mask uint8) error {
	for n, nlri := range context.RIBv4 {
		if nlri.Prefix == ipv4 && nlri.Length == mask {
			if n == (len(context.RIBv4) - 1) {
				context.RIBv4 = context.RIBv4[:n]
			} else {
				context.RIBv4 = append(context.RIBv4[:n], context.RIBv4[n+1:]...)
			}
			return nil
		}
	}
	return fmt.Errorf("route doesnt exist")
}

/*
This is BGPContext's fun because in future we could use info from context(for global lp,
aspath etc
*/
func (context *BGPContext) GenerateUpdateRouteV4(ipv4 IPV4_NLRI) BGPRoute {
	bgpRoute := BGPRoute{
		ORIGIN:     ORIGIN_IGP,
		LOCAL_PREF: 100,
	}
	bgpRoute.Routes = append(bgpRoute.Routes, ipv4)
	return bgpRoute
}

func (context *BGPContext) GenerateWithdrawRouteV4(ipv4 IPV4_NLRI) BGPRoute {
	bgpRoute := BGPRoute{}
	bgpRoute.WithdrawRoutes = append(bgpRoute.WithdrawRoutes, ipv4)
	return bgpRoute
}

func (context *BGPContext) AdvertiseRouteV4(ipv4 IPV4_NLRI) {
	for _, neighbour := range context.Neighbours {
		if neighbour.State == "Established" {
			neighbour.CmndChan <- BGPCommand{
				Cmnd:  "AdvertiseRouteV4",
				Route: context.GenerateUpdateRouteV4(ipv4)}
		}
	}
}

func (context *BGPContext) WithdrawRouteV4(ipv4 IPV4_NLRI) {
	for _, neighbour := range context.Neighbours {
		if neighbour.State == "Established" {
			neighbour.CmndChan <- BGPCommand{
				Cmnd:  "WithdrawRouteV4",
				Route: context.GenerateWithdrawRouteV4(ipv4)}
		}
	}
}

func (context *BGPContext) AdvertiseAllRoutesV4(cmndChan chan BGPCommand) {
	for _, route := range context.RIBv4 {
		/*
		   TODO: pack more that one route per update; implement check, that msg size is less then
		   bpg_max_msg_len
		*/
		cmndChan <- BGPCommand{
			Cmnd:  "AdvertiseRouteV4",
			Route: context.GenerateUpdateRouteV4(route)}
	}
}

func (context *BGPNeighbourContext) GetRouterID(fromConnect chan string) {
	//TODO: error handling
	ladr := <-fromConnect
	if ladr == "exit" {
		return
	}
	context.NextHop = ladr
	context.ToMainContext <- BGPCommand{Cmnd: "NewRouterID", CmndData: ladr}
	//TODO: send ladr to context (so it could be used as next_hop)
}

func StartBGPNeighbourContext(context *BGPNeighbourContext, passive bool,
	sockChans SockControlChans) {
	context.fsm.State = "Idle"
	var localSockChans SockControlChans
	if !passive {
		localSockChans.fromWriteError = make(chan uint8)
		localSockChans.toWriteError = make(chan uint8)
		localSockChans.readError = make(chan uint8)
		localSockChans.readChan = make(chan []byte)
		localSockChans.writeChan = make(chan []byte)
		localSockChans.controlChan = make(chan string)
	} else {
		localSockChans.fromWriteError = sockChans.fromWriteError
		localSockChans.toWriteError = sockChans.toWriteError
		localSockChans.readError = sockChans.readError
		localSockChans.readChan = sockChans.readChan
		localSockChans.writeChan = sockChans.writeChan
		localSockChans.controlChan = sockChans.controlChan
		context.NextHop = sockChans.localAddr
	}
	keepaliveFeedback := make(chan uint8)
	msgBuf := make([]byte, 0)
	context.fsm.Event("Start")
	context.fsm.KeepaliveTime = 30
	context.fsm.DelayOpenTime = 5
RECONNECT:
	if !passive {
		context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
			Cmnd:         "ActiveStartConnection",
			ResponseChan: localSockChans.controlChan}
		/*
					   we cant rcv resp from ToNeighbourContext chan, in case, when passiveConnection in established state
			           (it rewrites ToNeighbourContext chan in bgpneighbour struct)
		*/
		response := <-localSockChans.controlChan
		if response == "teardown" {
			return
		}
		go context.GetRouterID(localSockChans.controlChan)
		err := ConnectToNeighbour(context.NeighbourAddr,
			localSockChans.fromWriteError,
			localSockChans.toWriteError,
			localSockChans.readError,
			localSockChans.readChan,
			localSockChans.writeChan,
			localSockChans.controlChan)

		if err != nil {
			if err == CANT_CONNECT_ERROR {
				localSockChans.controlChan <- "exit"
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
	}

	loop := 1
	if context.RouterID == 0 {
		for loop == 1 {
			if !passive {
				context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
					Cmnd: "GetRouterID"}
			} else {
				context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
					Cmnd: "GetRouterIDPassive"}

			}
			resp := <-context.ToNeighbourContext

			switch resp.Cmnd {
			case "RouterID":
				if resp.CmndData != "0" {
					loop = 0
					id, _ := strconv.ParseUint(resp.CmndData, 10, 32)
					context.RouterID = uint32(id)
				} else {
					time.Sleep(1 * time.Second)
				}
			}
		}
	}
	if !passive {
		context.ToMainContext <- BGPCommand{From: context.NeighbourAddr, Cmnd: "ActiveConnected"}
		GenerateOpenMsg(context, localSockChans.writeChan, "OpenSent")
	}
	loop = 1
	for loop == 1 {
		select {
		case msgFromMainContext := <-context.ToNeighbourContext:
			if context.fsm.State == "Established" {
				if msgFromMainContext.Cmnd == "AdvertiseRouteV4" ||
					msgFromMainContext.Cmnd == "WithdrawRouteV4" {
					route := msgFromMainContext.Route
					err := route.AddV4NextHop(context.NextHop)
					if err != nil {
						continue
					}

					data, err := EncodeUpdateMsg(&route)
					if err != nil {
						continue
					}

					localSockChans.writeChan <- data
				}
			}
		case bgpMsg := <-localSockChans.readChan:
			msgBuf = append(msgBuf, bgpMsg...)
			for {
				if len(msgBuf) < MSG_HDR_SIZE {
					break
				}
				hdr, err := DecodeMsgHeader(msgBuf)
				if err != nil {
					SendNotification(context, "MsgHeaderError", localSockChans,
						BGP_MSG_HEADER_ERROR, BGP_MH_ERROR_BADTYPE)
					msgBuf = msgBuf[:0]
					//TODO: here and bellow: lots of copy-paste. find a better way to deal with
					if passive {
						context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
							Cmnd: "PassiveClossed"}
						goto PASSIVE_TEARDOWN
					} else {
						context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
							Cmnd: "ActiveClossed"}
						goto RECONNECT
					}
				}
				if len(msgBuf) < int(hdr.Length) {
					break
				}
				switch hdr.Type {
				case BGP_OPEN_MSG:
					openMsg, err := DecodeOpenMsg(msgBuf[MSG_HDR_SIZE:hdr.Length])
					if err != nil {
						//TODO: proper error subcodes; here and below
						SendNotification(context, "OpenError", localSockChans,
							BGP_OPEN_MSG_ERROR, BGP_GENERIC_ERROR)
						msgBuf = msgBuf[:0]
						if passive {
							context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
								Cmnd: "PassiveClossed"}
							goto PASSIVE_TEARDOWN

						} else {
							context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
								Cmnd: "ActiveClossed"}
							goto RECONNECT
						}
					}
					state := context.fsm.Event("OpenRcv")
					chckResult := PerformCollisionCheck(context, passive, &openMsg)
					if chckResult == "teardown" {
						SendNotification(context, "Collision", localSockChans,
							BGP_CASE_ERROR, BGP_CASE_ERROR_COLLISION)
						msgBuf = msgBuf[:0]
						if passive {
							context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
								Cmnd: "PassiveClossed"}
						} else {
							context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
								Cmnd: "ActiveClossed"}
						}
						return
					}
					switch state {
					case "OpenKA":
						context.fsm.KeepaliveTime = uint32(openMsg.HoldTime / 3)
						context.fsm.HoldTime = uint32(openMsg.HoldTime)
						err := GenerateOpenMsg(context, localSockChans.writeChan, "")
						if err != nil {
							SendNotification(context, "OpenSendError", localSockChans,
								BGP_OPEN_MSG_ERROR, BGP_GENERIC_ERROR)
							msgBuf = msgBuf[:0]
							if passive {
								context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
									Cmnd: "PassiveClossed"}
								goto PASSIVE_TEARDOWN

							} else {
								context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
									Cmnd: "ActiveClossed"}
								goto RECONNECT
							}
						}
						encodedKA := GenerateKeepalive()
						localSockChans.writeChan <- encodedKA
					case "Keepalive":
						encodedKA := GenerateKeepalive()
						localSockChans.writeChan <- encodedKA
					default:
						SendNotification(context, "OpenError", localSockChans,
							BGP_FSM_ERROR, BGP_GENERIC_ERROR)
						msgBuf = msgBuf[:0]
						if passive {
							context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
								Cmnd: "PassiveClossed"}
							goto PASSIVE_TEARDOWN

						} else {
							context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
								Cmnd: "ActiveClossed"}
							goto RECONNECT
						}
					}
				case BGP_UPDATE_MSG:
					updMsg, err := DecodeUpdateMsg(msgBuf[:hdr.Length])
					if err != nil {
						SendNotification(context, "UpdateError", localSockChans,
							BGP_UPDATE_MSG_ERROR, BGP_GENERIC_ERROR)
						msgBuf = msgBuf[:0]
						if passive {
							context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
								Cmnd: "PassiveClossed"}
							goto PASSIVE_TEARDOWN
						} else {
							context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
								Cmnd: "ActiveClossed"}
							goto RECONNECT
						}
					}
					state := context.fsm.Event("Update")
					if state != "Established" {
						SendNotification(context, "UpdateError", localSockChans,
							BGP_FSM_ERROR, BGP_GENERIC_ERROR)
						msgBuf = msgBuf[:0]
						if passive {
							context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
								Cmnd: "PassiveClossed"}
							goto PASSIVE_TEARDOWN
						} else {
							context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
								Cmnd: "ActiveClossed"}
							goto RECONNECT
						}
					}
					PrintBgpUpdate(&updMsg)
				case BGP_NOTIFICATION_MSG:
					CloseSockets(context, localSockChans)
					if context.fsm.State == "Established" {
						keepaliveFeedback <- uint8(1)
					}
					msgBuf = msgBuf[:0]
					context.fsm.Event("Start")
					//TODO: fix hardcode
					time.Sleep(10 * time.Second)
					if passive {
						context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
							Cmnd: "PassiveClossed"}
						goto PASSIVE_TEARDOWN
					} else {
						context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
							Cmnd: "ActiveClossed"}
						goto RECONNECT
					}
				case BGP_KEEPALIVE_MSG:
					state := context.fsm.Event("Keepalive")
					if state == "Established" {
						if passive {
							context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
								Cmnd: "PassiveEstablished"}
						} else {
							context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
								Cmnd: "Established"}
						}
						go SendKeepalive(localSockChans.writeChan,
							context.fsm.KeepaliveTime,
							keepaliveFeedback)
					}
				}
				msgBuf = msgBuf[hdr.Length:]
			}
		}
	}
PASSIVE_TEARDOWN:
	context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
		Cmnd: "PassiveTeardown"}
	return

}

func SendKeepalive(writeChan chan []byte, sleepTime uint32, feedbackChan chan uint8) {
	loop := 1
	ka := GenerateKeepalive()
	for loop == 1 {
		select {
		case <-time.After(time.Duration(sleepTime) * time.Second):
		case <-feedbackChan:
			loop = 0
			continue
		}
		select {
		case writeChan <- ka:
			continue
		case <-feedbackChan:
			loop = 0
			continue
		}
	}
}

func GenerateOpenMsg(context *BGPNeighbourContext, writeChan chan []byte,
	event string) error {
	openMsg := OpenMsg{Version: uint8(4), MyASN: uint16(context.ASN),
		BGPID: context.RouterID, HoldTime: uint16(context.fsm.HoldTime)}
	encodedOpen, err := EncodeOpenMsg(&openMsg)
	if err != nil {
		return err
	}
	writeChan <- encodedOpen
	if event != "" {
		context.fsm.Event(event)
	}
	return nil
}

func SendNotification(context *BGPNeighbourContext, event string,
	sockChans SockControlChans, eCode, eSubcode uint8) {
	notificationMsg := NotificationMsg{
		ErrorCode:    eCode,
		ErrorSubcode: eSubcode}
	encodedNotification, err := EncodeNotificationMsg(&notificationMsg)
	if err != nil {
		return
	}
	sockChans.writeChan <- encodedNotification
	sockChans.toWriteError <- 0
	//TODO: poc this; proper sync
	select {
	case <-sockChans.readError:
	default:
	}
	if context.fsm.State == "Established" {
		/*
				HACK. trying to protect ourself from deadlock, when main context trying to send something
			    for us.TODO: to think mb there is a better solution for that
		*/
	LOOP:
		for {
			select {
			case <-context.ToNeighbourContext:
			default:
				break LOOP
			}
		}
		context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
			Cmnd: "Down"}

	}
	context.fsm.Event("Start")
}

func CloseSockets(context *BGPNeighbourContext, sockChans SockControlChans) {
	sockChans.toWriteError <- 0
	//TODO: poc this; proper sync
	select {
	case <-sockChans.readError:
	default:
	}
	if context.fsm.State == "Established" {
	LOOP:
		for {
			select {
			case <-context.ToNeighbourContext:
			default:
				break LOOP
			}
		}
		context.ToMainContext <- BGPCommand{From: context.NeighbourAddr,
			Cmnd: "Down"}

	}

}

func PerformCollisionCheck(context *BGPNeighbourContext, passive bool, openMsg *OpenMsg) string {
	bgpCmnd := BGPCommand{From: context.NeighbourAddr, Cmnd: "CollisionCheck"}
	if passive {
		bgpCmnd.Cmnd = "PassiveCollisionCheck"
	}
	context.ToMainContext <- bgpCmnd
	response := <-context.ToNeighbourContext
	if response.Cmnd == "NoCollision" {
		return response.Cmnd
	}
	if context.RouterID < openMsg.BGPID {
		if !passive {
			return "teardown"
		} else {
			bgpCmnd.Cmnd = "PassiveWonCollisionDetection"
			context.ToMainContext <- bgpCmnd
			return "CollisionResolved"
		}
	} else {
		if !passive {
			return "CollisionResolved"
		} else {
			return "teardown"
		}
	}
}
