package VPN

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	v2net "v2ray.com/core/common/net"
)

func TestProtectedDialer_PrepareDomain(t *testing.T) {
	type args struct {
		domainName string
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
		{"", args{"baidu.com:80"}},
		// {"", args{"cloudflare.com:443"}},
		// {"", args{"apple.com:443"}},
		// {"", args{"110.110.110.110:443"}},
		// {"", args{"[2002:1234::1]:443"}},
	}
	d := NewPreotectedDialer()
	for _, tt := range tests {
		ch := make(chan struct{})
		t.Run(tt.name, func(t *testing.T) {
			go d.PrepareDomain(tt.args.domainName, ch)

			t.Log(d.currentIP())
			go d.NextIP()
			go d.NextIP()
			go d.NextIP()
			time.Sleep(time.Second)
			go d.NextIP()
			t.Log(d.currentIP())
		})
	}

	time.Sleep(time.Second)
}

type fakeSupportSet struct{}

func (f fakeSupportSet) Protect(int) int {
	return 0
}

func TestProtectedDialer_Dial(t *testing.T) {

	d := NewPreotectedDialer()
	d.SupportSet = fakeSupportSet{}

	tests := []struct {
		name    string
		wantErr bool
	}{
		// TODO: Add test cases.
		{"baidu.com:80", false},
		// {"cloudflare.com:80", false},
		// {"172.16.192.11:80", true},
		// {"172.16.192.10:80", true},
		// {"[2fff:4322::1]:443", true},
		// {"[fc00::1]:443", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan struct{})
			go d.PrepareDomain(tt.name, ch)

			var wg sync.WaitGroup

			dial := func() {
				defer wg.Done()
				dest, _ := v2net.ParseDestination("tcp:" + tt.name)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				conn, err := d.Dial(ctx, nil, dest, nil)
				if err != nil {
					t.Log(err)
					return
				}
				_host, _, _ := net.SplitHostPort(tt.name)
				fmt.Fprintf(conn, fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", _host))
				status, err := bufio.NewReader(conn).ReadString('\n')
				t.Logf("%#v, %#v\n", status, err)
				conn.Close()
			}

			for n := 0; n < 3; n++ {
				wg.Add(1)
				go dial()
				// time.Sleep(time.Millisecond * 10)
				// d.pendingMap[tt.name] = make(chan struct{})
			}

			wg.Wait()
		})
	}
}
