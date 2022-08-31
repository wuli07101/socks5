package utils

import (
	"io"
	"net"
)

func Relay(in, out net.Conn) {
	io.Copy(in, out)
	in.Close()
	out.Close()
}

