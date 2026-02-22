package request

import (
	"net"
	"net/http"
	"syscall"
	"time"

	"slickproxy/internal/config"
	"slickproxy/internal/userdb"
)

type Request struct {
	Host          string
	Domain        string
	EndPort       string
	ClientIp      net.IP
	Port          uint16
	LocalIP       net.IP
	Type          string
	Bytes         int64
	InBytes       int64
	OutBytes      int64
	Success       bool
	RawRequest    *http.Request
	Credentials   AuthenticationCredentials
	Timestamp     int64
	Conn          net.Conn
	UpstreamProxy config.ProxyConfigEntry
	Attempts      int
	Error         string
}

type ProxyConn struct {
	Conn net.Conn
	Fd   int
}

type AuthenticationCredentials struct {
	User            string
	UserPart        string
	Country         string
	Session         string
	Time            int
	Password        string
	City            string
	State           string
	IpMode          userdb.IPVersion
	Mobile          bool
	UserDetail      *userdb.User
	Code            string
	OriginalSession string
}

func NewRequest(conn net.Conn, connType string) Request {
	clientIp := conn.RemoteAddr().(*net.TCPAddr)
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	return Request{
		Conn:      conn,
		ClientIp:  clientIp.IP,
		Port:      uint16(localAddr.Port),
		LocalIP:   localAddr.IP,
		Timestamp: time.Now().Unix(),
		Type:      connType,
	}
}
func NewProxyConn(conn net.Conn, fd int) ProxyConn {
	return ProxyConn{
		Conn: conn,
		Fd:   fd,
	}
}

func (r *Request) Close() error {
	_ = r.Conn.Close()

	return nil
}

func (r *ProxyConn) Close() error {
	syscall.Close(r.Fd)
	r.Conn.Close()
	return nil
}
