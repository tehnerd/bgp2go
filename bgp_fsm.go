package bgp2go

/*
   Lots of fields for the future (mb) implementation
*/
type FSM struct {
	State               string
	DelayOpenTime       uint32
	ConnectRetryCounter uint32
	ConnectRetryTimer   uint32
	ConnectRetryTime    uint32
	HoldTimer           uint32
	HoldTime            uint32
	KeepaliveTimer      uint32
	KeepaliveTime       uint32
}

/*
   This is very(VERY; in most cases not even honors rfc 4271)
   simple bgp's FSM. but should works for my
   current use cases. if neeed, it will be update and/or totally
   rewriten.
*/
func (fsm *FSM) Event(event string) string {
	switch event {
	case "Start":
		fsm.State = "Connect"
		return "Connect"
	case "OpenRcv":
		if fsm.State == "Connect" {
			fsm.State = "OpenConfirm"
			// we must send back open msg + keepalive
			return "OpenKA"
		} else if fsm.State == "OpenSent" {
			return "Keepalive"
		}
	case "OpenSent":
		if fsm.State == "Connect" {
			fsm.State = "OpenSent"
			return "WaitConfirm"
		}
	case "Keepalive":
		if fsm.State == "OpenConfirm" || fsm.State == "OpenSent" {
			fsm.State = "Established"
			return "Established"
		} else if fsm.State == "Established" {
			return "Keepalive"
		}
	case "Update":
		if fsm.State == "Established" {
			return "Established"
		}
	//Any type of errors. mostly placeholder
	default:
		fsm.State = "Connect"
		return "Notification"
	}
	fsm.State = "Connect"
	return "Generic FSM Error"
}
