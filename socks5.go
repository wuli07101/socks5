package socks5

import (
	"github.com/wuli07101/socks5/utils"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	ipV4            = 1
	domainName      = 3
	ipV6            = 4
	connectMethod   = 1
	bindMethod      = 2
	associateMethod = 3
	// The maximum packet size of any udp Associate packet, based on ethernet's max size,
	// minus the IP and UDP headers. IPv4 has a 20 byte header, UDP adds an
	// additional 4 bytes.  This is a total overhead of 24 bytes.  Ethernet's
	// max packet size is 1500 bytes,  1500 - 24 = 1476.
	maxUDPPacketSize = 1476
)

const (
	succeeded uint8 = iota
	serverFailure
	notAllowed
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

const (
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

type Socks5 struct {
	IsVerify   bool
	Auth       func(string,string) (bool,error)
}

//new conn
func (c *Socks5) HandleConn(client net.Conn) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(client, buf); err != nil {
		log.Println("negotiation err", err)
		client.Close()
		return
	}

	if version := buf[0]; version != 5 {
		log.Println("only support socks5, request from: ", client.RemoteAddr())
		client.Close()
		return
	}
	nMethods := buf[1]

	methods := make([]byte, nMethods)
	if len, err := client.Read(methods); len != int(nMethods) || err != nil {
		log.Println("wrong method")
		client.Close()
		return
	}
	if c.IsVerify {
		buf[1] = UserPassAuth
		client.Write(buf)
		if err := c.auth(client); err != nil {
			client.Close()
			log.Println("验证失败：", err)
			return
		}
	} else {
		buf[1] = 0
		client.Write(buf)
	}

	c.handleRequest(client)
}

//req
func (c *Socks5) handleRequest(client net.Conn) {
	header := make([]byte, 3)

	_, err := io.ReadFull(client, header)

	if err != nil {
		log.Println("illegal request", err)
		client.Close()
		return
	}

	switch header[1] {
	case connectMethod:
		c.handleConnect(client)
	case bindMethod:
		c.handleBind(client)
	case associateMethod:
		c.handleUDP(client)
	default:
		c.sendReply(client, commandNotSupported)
		client.Close()
	}
}

//reply
func (c *Socks5) sendReply(client net.Conn, rep uint8) {
	reply := []byte{
		5,
		rep,
		0,
		1,
	}

	localHost := "0.0.0.0"
	localPort := "8080"
	ipBytes := net.ParseIP(localHost).To4()
	nPort, _ := strconv.Atoi(localPort)
	reply = append(reply, ipBytes...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(nPort))
	reply = append(reply, portBytes...)

	client.Write(reply)
}

//do conn
func (c *Socks5) doConnect(client net.Conn, command uint8) (proxyConn net.Conn, err error) {
	addrType := make([]byte, 1)
	client.Read(addrType)
	var host string
	switch addrType[0] {
	case ipV4:
		ipv4 := make(net.IP, net.IPv4len)
		client.Read(ipv4)
		host = ipv4.String()
	case ipV6:
		ipv6 := make(net.IP, net.IPv6len)
		client.Read(ipv6)
		host = ipv6.String()
	case domainName:
		var domainLen uint8
		binary.Read(client, binary.BigEndian, &domainLen)
		domain := make([]byte, domainLen)
		client.Read(domain)
		host = string(domain)
	default:
		c.sendReply(client, addrTypeNotSupported)
		err = errors.New("Address type not supported")
		return nil, err
	}

	var port uint16
	binary.Read(client, binary.BigEndian, &port)
	// connect to host
	proxyConn, err =net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))),time.Duration(3) * time.Second)
	//log.Println("host: ", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	
	c.sendReply(client, succeeded)

	return proxyConn, err
}

//conn
func (c *Socks5) handleConnect(client net.Conn) {
	proxyConn, err := c.doConnect(client, connectMethod)
	if err != nil {
		client.Close()
	} else {
		go utils.Relay(proxyConn, client)
		utils.Relay(client, proxyConn)
	}
}

// passive mode
func (c *Socks5) handleBind(client net.Conn) {
}

//udp
func (c *Socks5) handleUDP(client net.Conn) {
	log.Println("UDP Associate")
	/*
	   +----+------+------+----------+----------+----------+
	   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	   +----+------+------+----------+----------+----------+
	   | 2  |  1   |  1   | Variable |    2     | Variable |
	   +----+------+------+----------+----------+----------+
	*/
	buf := make([]byte, 3)
	client.Read(buf)
	// relay udp datagram silently, without any notification to the requesting client
	if buf[2] != 0 {
		// does not support fragmentation, drop it
		log.Println("does not support fragmentation, drop")
		dummy := make([]byte, maxUDPPacketSize)
		client.Read(dummy)
	}

	proxyConn, err := c.doConnect(client, associateMethod)
	if err != nil {
		client.Close()
	} else {
		go utils.Relay(proxyConn, client)
		utils.Relay(client, proxyConn)
	}
}

//socks5 auth
func (c *Socks5) auth(client net.Conn) error {
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(client, header, 2); err != nil {
		return err
	}
	if header[0] != userAuthVersion {
		return errors.New("验证方式不被支持")
	}
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(client, user, userLen); err != nil {
		return err
	}
	if _, err := client.Read(header[:1]); err != nil {
		return errors.New("密码长度获取错误")
	}
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(client, pass, passLen); err != nil {
		return err
	}
	if isPass,_:= c.Auth(string(user),string(pass)); isPass == true {
		if _, err := client.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return err
		}
		return nil
	} else {
		if _, err := client.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return err
		}
		return errors.New("验证不通过")
	}
	return errors.New("未知错误")
}
