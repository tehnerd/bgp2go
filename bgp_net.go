package bgp

/* Generic networking routines for bgp */

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

const (
	BGP_PORT = "179"
)

var (
	CANT_CONNECT_ERROR = errors.New("cant connect to remote peer")
)

type SockControlChans struct {
	fromWriteError chan uint8
	toWriteError   chan uint8
	readError      chan uint8
	readChan       chan []byte
	writeChan      chan []byte
	controlChan    chan string
}

func (sockChans *SockControlChans) Init() {
	sockChans.fromWriteError = make(chan uint8)
	sockChans.toWriteError = make(chan uint8)
	sockChans.readError = make(chan uint8)
	sockChans.readChan = make(chan []byte)
	sockChans.writeChan = make(chan []byte)
	sockChans.controlChan = make(chan string)

}

func ConnectToNeighbour(neighbour string,
	fromWriteError, toWriteError, readError chan uint8,
	readChan, writeChan chan []byte,
	controlChan chan string) error {
	remoteAddr := strings.Join([]string{neighbour, BGP_PORT}, ":")
	tcpAddr, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil {
		return fmt.Errorf("cant resolve remote address: %v\n", err)
	}
	tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return CANT_CONNECT_ERROR
	}
	//We wont to mark our bgp packets with CS6
	fd, _ := tcpConn.File()
	syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_TOS, 192)
	fd.Close()
	localAddr := tcpConn.LocalAddr()
	//sending our localaddress; so it can be used as NEXT_HOP
	controlChan <- strings.Split(localAddr.String(), ":")[0]
	go ReadFromNeighbour(tcpConn, readChan, readError)
	go WriteToNeighbour(tcpConn, writeChan, fromWriteError, toWriteError)
	return nil
}

func ReadFromNeighbour(sock *net.TCPConn, readChan chan []byte,
	readError chan uint8) {
	loop := 1
	buf := make([]byte, 65535)
	for loop == 1 {
		bytes, err := sock.Read(buf)
		if err != nil {
			readError <- uint8(1)
			loop = 0
			continue
		}
		readChan <- buf[:bytes]
	}
}

func WriteToNeighbour(sock *net.TCPConn, writeChan chan []byte,
	fromWriteError, toWriteError chan uint8) {
	loop := 1
	for loop == 1 {
		select {
		case msg := <-writeChan:
		WRITE:
			bytes, err := sock.Write(msg)
			if err != nil {
				select {
				case fromWriteError <- uint8(1):
				case <-toWriteError:
				}
				loop = 0
				continue
			}
			if bytes != len(msg) {
				msg = msg[bytes:]
				goto WRITE
			}
		case <-toWriteError:
			loop = 0
		}
	}

	/*
	   it could be already clossed (for example connection has been closed from the remote side
	   however we could initate closing as well (for example error in msg parsing)
	   it both cases(closing a working connection, or clossing a clossed) that shouldnt be a problem.
	*/
	sock.Close()
}

/*
   simple_bgp_injector specific routines

*/

func BGPListenForConnection(toMainContext chan BGPCommand) error {
	addr := strings.Join([]string{"", BGP_PORT}, ":")
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	//TODO: log instead of return
	if err != nil {
		return fmt.Errorf("cant parse local address: %v\n", err)
	}
	servSock, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return fmt.Errorf("cant bind to local address: %v\n", err)
	}
	for {
		sock, err := servSock.AcceptTCP()
		if err != nil {
			sock.Close()
			continue
		}
		go ProcessPeerConection(sock, toMainContext)
	}
}

func ProcessPeerConection(sock *net.TCPConn, toMainContext chan BGPCommand) {
	radr := strings.Split(sock.RemoteAddr().String(), ":")[0]
	sockChans := SockControlChans{}
	sockChans.Init()
	toMainContext <- BGPCommand{Cmnd: "NewConnection", CmndData: radr,
		ResponseChan: sockChans.controlChan}
	response := <-sockChans.controlChan
	if response == "teardown" {
		sock.Close()
		return
	}
	ladr := strings.Split(sock.LocalAddr().String(), ":")[0]
	toMainContext <- BGPCommand{Cmnd: "NewRouterID", CmndData: ladr}
	go ReadFromNeighbour(sock, sockChans.readChan, sockChans.readError)
	go WriteToNeighbour(sock, sockChans.writeChan, sockChans.fromWriteError,
		sockChans.toWriteError)
	toMainContext <- BGPCommand{Cmnd: "AddPassiveNeighbour", CmndData: radr,
		sockChans: sockChans}

}
