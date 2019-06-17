package VPN

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	v2net "v2ray.com/core/common/net"
	v2internet "v2ray.com/core/transport/internet"
)

type protectSet interface {
	Protect(int) int
}

type resolved struct {
	IPS   []net.IP
	Port  int
	Index int
}

func (r *resolved) CurentIP() net.IP {
	return r.IPS[r.Index]
}

func (r *resolved) NextIP() {
	if len(r.IPS) > 0 {
		r.Index++
	}
	if r.Index >= len(r.IPS) {
		r.Index = 0
	}
}

func newResolved(ips []net.IP, port int) *resolved {
	r := &resolved{
		IPS:   ips,
		Port:  port,
		Index: 0,
	}
	return r
}

func NewPreotectedDialer() *VPNProtectedDialer {
	d := &VPNProtectedDialer{
		serverMap: make(map[string]*resolved),
	}
	return d
}

type VPNProtectedDialer struct {
	currentServer string
	serverMap     map[string]*resolved
	SupportSet    protectSet
}

func (d *VPNProtectedDialer) PrepareDomain(domainName string) {
	d.currentServer = domainName
	log.Printf("Preparing Domain: %s", domainName)
	_host, _port, serr := net.SplitHostPort(domainName)
	_iport, perr := strconv.Atoi(_port)
	if serr != nil || perr != nil {
		log.Printf("PrepareDomain DomainName Err: %v|%v", serr, perr)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// prefer native lookup on Android
	r := net.Resolver{PreferGo: false}
	if addrs, err := r.LookupIPAddr(ctx, _host); err == nil {
		ips := make([]net.IP, len(addrs))
		for i, ia := range addrs {
			ips[i] = ia.IP
		}
		d.serverMap[domainName] = newResolved(ips, _iport)
		log.Printf("Prepare Result:\n Domain: %s\n Port: %d\n IPs: %v\n", _host, _iport, ips)
	} else {
		log.Printf("PrepareDomain LookupIP Err: %v, retrying..", err)
		time.Sleep(3 * time.Second)
		go d.PrepareDomain(domainName)
	}
}

func (d *VPNProtectedDialer) prepareFd(network v2net.Network) (fd int, err error) {
	switch network {
	case v2net.Network_TCP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
		d.SupportSet.Protect(fd)
	case v2net.Network_UDP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		d.SupportSet.Protect(fd)
	default:
		err = fmt.Errorf("unknow network")
	}
	return
}

func (d VPNProtectedDialer) Dial(ctx context.Context,
	src v2net.Address,
	dest v2net.Destination, sockopt *v2internet.SocketConfig) (net.Conn, error) {
	network := dest.Network.SystemString()
	Address := dest.NetAddr()

	// lookup v2ray server cache
	if res, ok := d.serverMap[Address]; ok {
		if Address == d.currentServer {
			if fd, err := d.prepareFd(dest.Network); err == nil {
				conn, err := d.fdConn(ctx, res.CurentIP(), res.Port, fd)
				if err != nil {
					if strings.Index(err.Error(), "unreachable") > 0 {
						res.NextIP()
					}
				}
				return conn, err
			} else {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("current server changed, fast shutting down old conns")
		}
	}

	var _port int
	var _ip net.IP

	if dest.Network == v2net.Network_TCP {
		addr, err := net.ResolveTCPAddr(network, Address)
		if err != nil {
			return nil, err
		}
		log.Println("Not Using Prepared: TCP,", Address)
		_port = addr.Port
		_ip = addr.IP.To16()
	} else if dest.Network == v2net.Network_UDP {
		addr, err := net.ResolveUDPAddr(network, Address)
		if err != nil {
			return nil, err
		}
		log.Println("Not Using Prepared: UDP,", Address)
		_port = addr.Port
		_ip = addr.IP.To16()
	} else {
		return nil, fmt.Errorf("unsupported network type")
	}

	if fd, err := d.prepareFd(dest.Network); err == nil {
		return d.fdConn(ctx, _ip, _port, fd)
	} else {
		return nil, err
	}
}

func (d VPNProtectedDialer) fdConn(ctx context.Context, ip net.IP, port int, fd int) (net.Conn, error) {

	d.SupportSet.Protect(fd)
	sa := &unix.SockaddrInet6{
		Port: port,
	}
	copy(sa.Addr[:], ip)

	if err := unix.Connect(fd, sa); err != nil {
		log.Printf("fdConn Connect Close Fd: %d Err: %v", fd, err)
		unix.Close(fd)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "Socket")
	conn, err := net.FileConn(file)
	if err != nil {
		log.Printf("fdConn FileConn Close Fd: %d Err: %v", fd, err)
		file.Close()
		unix.Close(fd)
		return nil, err
	}

	go func() {
		select {
		case <-ctx.Done():
			file.Close()
			unix.Close(fd)
		}
		return
	}()

	return conn, nil
}

func init() {
	rand.Seed(time.Now().Unix())
}
