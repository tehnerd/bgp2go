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
