package VPN

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
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
	domain       string
	IPs          []net.IP
	Port         int
	ipIdx        uint8
	ipLock       sync.Mutex
	lastSwitched time.Time
}

// NextIP switch to another resolved result.
// there still be race-condition here if multiple err concurently occured
// may cause idx keep switching,
// but that's an outside error can hardly handled here
func (r *resolved) NextIP() {
	r.ipLock.Lock()
	defer r.ipLock.Unlock()

	if len(r.IPs) > 1 {

		// throttle, don't switch too quickly
		now := time.Now()
		if now.Sub(r.lastSwitched) < time.Second*5 {
			log.Println("switch too quickly")
			return
		}
		r.lastSwitched = now
		r.ipIdx++

	} else {
		return
	}

	if r.ipIdx >= uint8(len(r.IPs)) {
		r.ipIdx = 0
	}

	cur := r.currentIP()
	log.Printf("switched to next IP: %s", cur)
}

func (r *resolved) currentIP() net.IP {
	if len(r.IPs) > 0 {
		return r.IPs[r.ipIdx]
	}

	return nil
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

	vServer    *resolved
	SupportSet protectSet
}

func (d *ProtectedDialer) lookupAddr(Address string) (*resolved, error) {
	log.Println("lookup addr: ", Address)

	host, port, serr := net.SplitHostPort(Address)
	_iport, perr := strconv.Atoi(port)
	if serr != nil || perr != nil {
		err := fmt.Errorf("%v\n%v", serr, perr)
		log.Printf("PrepareDomain DomainName Err: %v", err)
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// prefer native lookup on Android
	r := net.Resolver{PreferGo: false}
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("domain %s Failed to resolve", Address)
	}

	IPs := make([]net.IP, len(addrs))
	for i, ia := range addrs {
		IPs[i] = ia.IP
	}

	rs := &resolved{
		domain: host,
		IPs:    IPs,
		Port:   _iport,
	}

	return rs, nil
}

// PrepareDomain caches direct v2ray server host
func (d *ProtectedDialer) PrepareDomain(domainName string, closeCh <-chan struct{}) {

	log.Printf("Preparing Domain: %s", domainName)

	defer close(d.resolveChan)
	d.currentServer = domainName

	for {
		resolved, err := d.lookupAddr(domainName)
		if err != nil {
			log.Printf("PrepareDomain err: %v\n", err)
			select {
			case <-closeCh:
				log.Printf("PrepareDomain exit due to v2ray closed")
				return
			case <-time.After(time.Second * 2):
			}
			continue
		}

		d.vServer = resolved
		log.Printf("Prepare Result:\n Domain: %s\n Port: %d\n IPs: %v\n",
			resolved.domain, resolved.Port, resolved.IPs)
		return
	}
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
	if strings.Compare(Address, d.currentServer) == 0 {
		if d.vServer == nil {
			log.Println("Dial pending prepare  ...", Address)
			<-d.resolveChan
		}

		if d.vServer == nil {
			// shoud not happeded
			return nil, fmt.Errorf("fail to prepare domain %s", d.currentServer)
		}

		fd, err := d.getFd(dest.Network)
		if err != nil {
			return nil, err
		}

		curIP := d.vServer.currentIP()
		conn, err := d.fdConn(ctx, curIP, d.vServer.Port, fd)
		if err != nil {
			d.vServer.NextIP()
			return nil, err
		}
		log.Printf("Using Prepared: %s", curIP)
		return conn, nil
	}

	// v2ray connecting to "domestic" servers, won't cache
	log.Printf("Not Using Prepared: %s,%s", network, Address)
	resolved, err := d.lookupAddr(Address)
	if err != nil {
		return nil, err
	}

	fd, err := d.getFd(dest.Network)
	if err != nil {
		return nil, err
	}
	return d.fdConn(ctx, resolved.IPs[0], resolved.Port, fd)
}

func (d *ProtectedDialer) fdConn(ctx context.Context, ip net.IP, port int, fd int) (net.Conn, error) {

	// call android VPN service to "protect" the fd connecting straight out
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
		// wait context until cancel
		// clean up fd
		<-ctx.Done()

		file.Close()
		unix.Close(fd)
		return
	}()

	return conn, nil
}
