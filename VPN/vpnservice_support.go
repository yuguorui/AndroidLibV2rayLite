package VPN

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	v2net "v2ray.com/core/common/net"
	v2internet "v2ray.com/core/transport/internet"
)

type protectSet interface {
	Protect(int) int
}

type resolved struct {
}

// NewPreotectedDialer ...
func NewPreotectedDialer() *ProtectedDialer {
	d := &ProtectedDialer{
		resolveChan: make(chan struct{}),
	}
	return d
}

// ProtectedDialer ...
type ProtectedDialer struct {
	currentServer string
	resolveChan   chan struct{}

	IPs    []net.IP
	port   int
	ipIdx  uint8
	ipLock sync.Mutex

	SupportSet protectSet
}

// NextIP switch to another resolved result.
// there still be race-condition here if multiple err concurently occured
// may cause idx keep switching,
// but that's an outside error can hardly handled here
func (d *ProtectedDialer) NextIP() {
	d.ipLock.Lock()
	defer d.ipLock.Unlock()

	if len(d.IPs) > 1 {
		d.ipIdx++
	} else {
		return
	}

	if d.ipIdx >= uint8(len(d.IPs)) {
		d.ipIdx = 0
	}
	cur := d.currentIP()
	log.Printf("switched to next IP: %s", cur)
}

func (d *ProtectedDialer) lookupAddr(host string) error {
	log.Println("lookup addr: ", host)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// prefer native lookup on Android
	r := net.Resolver{PreferGo: false}
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return err
	}

	d.IPs = make([]net.IP, len(addrs))
	for i, ia := range addrs {
		d.IPs[i] = ia.IP
	}

	return nil
}

// PrepareDomain caches direct v2ray server host
func (d *ProtectedDialer) PrepareDomain(domainName string, closeCh <-chan struct{}) {

	log.Printf("Preparing Domain: %s", domainName)

	defer close(d.resolveChan)
	d.currentServer = domainName

	_host, _port, serr := net.SplitHostPort(domainName)
	_iport, perr := strconv.Atoi(_port)
	if serr != nil || perr != nil {
		log.Printf("PrepareDomain DomainName Err: %v|%v", serr, perr)
		return
	}
	d.port = _iport

	for {
		err := d.lookupAddr(_host)
		if err != nil {
			log.Printf("PrepareDomain err: %v\n", err)
			select {
			case <-closeCh:
				log.Printf("PrepareDomain exit due to closed")
				return
			case <-time.After(time.Second * 2):
			}
			continue
		}

		log.Printf("Prepare Result:\n Domain: %s\n Port: %d\n IPs: %v\n", _host, _iport, d.IPs)
		return
	}
}

func (d *ProtectedDialer) currentIP() net.IP {
	if len(d.IPs) > 0 {
		return d.IPs[d.ipIdx]
	}

	return nil
}

func (d *ProtectedDialer) getFd(network v2net.Network) (fd int, err error) {
	switch network {
	case v2net.Network_TCP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	case v2net.Network_UDP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	default:
		err = fmt.Errorf("unknow network")
	}
	return
}

// Dial exported as the protected dial method
func (d *ProtectedDialer) Dial(ctx context.Context,
	src v2net.Address, dest v2net.Destination, sockopt *v2internet.SocketConfig) (net.Conn, error) {

	network := dest.Network.SystemString()
	Address := dest.NetAddr()

	// v2ray server address,
	// try to connect fixed IP if multiple IP parsed from domain,
	// and switch to next IP if error occurred
	if Address == d.currentServer {
		if len(d.IPs) == 0 {
			log.Println("Dial pending prepare  ...", Address)
			<-d.resolveChan
		}

		curIP := d.currentIP()

		if curIP == nil {
			return nil, fmt.Errorf("fail to prepare domain %s", d.currentServer)
		}

		fd, err := d.getFd(dest.Network)
		if err != nil {
			return nil, err
		}

		conn, err := d.fdConn(ctx, curIP, d.port, fd)
		if err != nil {
			d.NextIP()
			return nil, err
		}
		log.Printf("Using Prepared: %s", curIP)
		return conn, err
	}

	// v2ray connecting to "domestic" servers, won't cache
	var _port int
	var _ip net.IP

	switch dest.Network {
	case v2net.Network_TCP:
		addr, err := net.ResolveTCPAddr(network, Address)
		if err != nil {
			return nil, err
		}
		_port = addr.Port
		_ip = addr.IP.To16()
	case v2net.Network_UDP:
		addr, err := net.ResolveUDPAddr(network, Address)
		if err != nil {
			return nil, err
		}
		_port = addr.Port
		_ip = addr.IP.To16()
	default:
		return nil, fmt.Errorf("unsupported network type")
	}

	log.Printf("Not Using Prepared: %s,%s", network, Address)
	fd, err := d.getFd(dest.Network)
	if err != nil {
		return nil, err
	}
	return d.fdConn(ctx, _ip, _port, fd)
}

func (d *ProtectedDialer) fdConn(ctx context.Context, ip net.IP, port int, fd int) (net.Conn, error) {
	d.SupportSet.Protect(fd)

	sa := &unix.SockaddrInet6{
		Port: port,
	}
	copy(sa.Addr[:], ip)

	if err := unix.Connect(fd, sa); err != nil {
		log.Printf("fdConn unix.Connect err, Close Fd: %d Err: %v", fd, err)
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
		// wait ctx
		<-ctx.Done()

		file.Close()
		unix.Close(fd)
		return
	}()

	return conn, nil
}
