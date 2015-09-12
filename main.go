// Command dnsproxy is a DNS server which replies with fake IPs to tunnel connections.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/miekg/dns"
)

var (
	addrpool = struct {
		sync.RWMutex
		// The pool of avaiable addresses.
		pool lru.Cache
		// Secondary index to check if we have a particular domain.
		domains map[string]net.IP
		// Used to retrieve the LRU addr from pool on eviction.
		freeaddr net.IP
	}{
		domains: make(map[string]net.IP),
	}

	// Upstream DNS relay.
	dnsserver string
	// Address of the remote-end of the tunnel.
	tunneladdr string
)

// resolver responds to all DNS A record requests with an address from addrpool,
// maintaining  a mapping to the domain's actual IP address.
func resolver(w dns.ResponseWriter, req *dns.Msg) {
	msg, err := dns.Exchange(req, dnsserver)
	if err != nil {
		log.Printf("Couldn't query: %v", err)
		// TODO return error Msg
		return
	}

	for _, rr := range msg.Answer {
		// TODO do this for only one record, delete the others.
		if rr.Header().Rrtype == dns.TypeA {
			a := rr.(*dns.A)

			addrpool.Lock()
			addr, ok := addrpool.domains[a.Hdr.Name]
			// Maybe we should also Get it on ok to push it up the LRU cache.
			if !ok {
				addrpool.pool.RemoveOldest()
				addrpool.pool.Add(ip4touint32(addrpool.freeaddr), a.Hdr.Name)
				log.Printf("Adding %v -> %s", addrpool.freeaddr, a.Hdr.Name)
				addr = addrpool.freeaddr
				addrpool.domains[a.Hdr.Name] = addr
			}
			addrpool.Unlock()

			log.Println("Type A:", a.A)
			a.A = addr
			a.Hdr.Ttl = 1
		}
	}

	w.WriteMsg(msg)
}

func ip4touint32(addr net.IP) uint32 {
	ip := addr.To4()
	return (uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) | (uint32(ip[2]) << 8) | uint32(ip[3])
}

func uint32toip4(addr uint32) net.IP {
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr))
}

// proxy handles the handles proxying a connection through a 'fake' IP address
// given out by our DNS server. Optionally, it tunnels it via a remote host.
func proxy(conn net.Conn) {
	defer conn.Close()
	host, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		log.Printf("Couldn't parse local address $v: %v", conn.LocalAddr(), err)
		return
	}
	localaddr := net.ParseIP(host)
	if localaddr == nil {
		log.Printf("Couldn't figure out IP of local address: %v", host)
		return
	}

	addrpool.RLock()
	destaddr, ok := addrpool.pool.Get(ip4touint32(localaddr))
	addrpool.RUnlock()
	if !ok {
		log.Printf("Couldn't find remote address for %v", localaddr)
		return
	}

	var destc net.Conn
	if tunneladdr != "" {
		// We're tunneling through a remote host, send a header first.
		hdr, err := json.Marshal(header{Destaddr: destaddr.(string) + ":" + port})
		if err != nil {
			log.Printf("Couldn't marshal header for tunnel: %v", err)
			return
		}
		destc, err = net.Dial("tcp", tunneladdr)
		if err != nil {
			log.Printf("Couldn't dial our tunnel remote: %v", err)
			return
		}
		log.Printf("Proxying %v to %v via %v", conn.RemoteAddr(), destaddr.(string)+":"+port, tunneladdr)
		_, err = destc.Write(hdr)
		if err != nil {
			log.Printf("Couldn't write header to tunnel remote: %v", err)
			return
		}
	} else {
		// No tunnel configured, just proxy connections directly.
		destc, err = net.Dial("tcp", destaddr.(string)+":"+port)
		if err != nil {
			log.Printf("Couldn't dial destination $v: %v", destaddr.(string), err)
			return
		}
		log.Printf("Proxying %v to %v", conn.RemoteAddr(), destc.RemoteAddr())
	}
	defer destc.Close()

	done := make(chan struct{})
	go func() {
		io.Copy(destc, conn)
		done <- struct{}{}
	}()
	io.Copy(conn, destc)
	<-done
}

// listenAndProxy listens on a pooled address, and proxies any connections
// according to the mapping in addr pool.
func listenAndProxy(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Couldn't listen for proxy connections: %v", err)
	}
	defer l.Close()
	var delay time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if max := time.Second; delay > max {
					delay = max
				}
				log.Printf("Couldn't accept proxy connection: %v; retrying in %v", err, delay)
				time.Sleep(delay)
				continue
			}
			log.Fatalf("Couldn't accept proxy connection: %v", err)
		}
		log.Printf("Accepted a connection from %v", conn.RemoteAddr())
		go proxy(conn)
	}
}

// header is the JSON header sent to the remote-end of the tunnel,
// preceding the body of the connection.
type header struct {
	Destaddr string
}

func tunnel(conn net.Conn) {
	defer conn.Close()

	// We start with a JSON header, currenly only has the dest addr.
	hdrdec := json.NewDecoder(conn)
	var hdr header
	err := hdrdec.Decode(&hdr)
	if err != nil {
		log.Printf("Couldn't parse tunnelled connection header: %v", err)
		return
	}

	destc, err := net.Dial("tcp", hdr.Destaddr)
	if err != nil {
		log.Printf("Couldn't dial destination $v: %v", hdr.Destaddr, err)
		return
	}
	defer destc.Close()

	log.Printf("Now tunnelling %v to %v", conn.RemoteAddr(), destc.RemoteAddr())
	done := make(chan struct{})
	go func() {
		io.Copy(destc, io.MultiReader(hdrdec.Buffered(), conn))
		done <- struct{}{}
	}()
	io.Copy(conn, destc)
	<-done
}

func listenAndTunnel(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("Couldn't listen for tunneled connections: %v", err)
	}
	defer l.Close()
	var delay time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if max := time.Second; delay > max {
					delay = max
				}
				log.Printf("Couldn't accept tunneled connection: %v; retrying in %v", err, delay)
				time.Sleep(delay)
				continue
			}
			return err
		}
		log.Printf("Accepted a connection from %v", conn.RemoteAddr())
		go tunnel(conn)
	}
}

func parseAndAddIPRange(r string) error {
	// TODO Finish this stub.
	return nil
}

func parseAndAddCIDR(r string) error {
	_, n, err := net.ParseCIDR(r)
	if err != nil {
		return err
	}
	addr := ip4touint32(n.IP)
	ones, bits := n.Mask.Size()
	size := uint32(1) << uint(bits-ones)
	for i := uint32(0); i < size; i++ {
		addrpool.pool.Add(addr+i, "--invalid--")
		log.Printf("Adding %v", uint32toip4(addr+i))
	}
	return nil
}

func parseAndAddIP(r string) error {
	addr := net.ParseIP(r)
	if addr == nil {
		return fmt.Errorf("invalid IP address")
	}
	addrpool.pool.Add(ip4touint32(addr), "--invalid--")
	log.Printf("Adding %v", addr)
	return nil
}

type StringList []string

func (s *StringList) String() string {
	return fmt.Sprint([]string(*s))
}

func (s *StringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	var listenports, ipranges StringList
	var remote = flag.Bool("remote", false, "Run as the remote-end of the tunnel.")
	var dnsaddr = flag.String("dns-addr", ":53", "Listen address for local DNS server.")
	flag.Var(&ipranges, "iprange", "The IP address range to use for the proxy pool. Acceptable "+
		"values are CIDR-style network addresses & single IP addresses. Can be set multiple "+
		"times for multiple ranges.")
	flag.Var(&listenports, "port", "TCP port to proxy. Can be set multiple times for multiple "+
		"ports.")
	flag.StringVar(&tunneladdr, "tunnel-addr", "", "Address for the remote-end of the tunnel.")
	flag.StringVar(&dnsserver, "upstream-dns-server", "8.8.8.8:53", "DNS server to rely our "+
		"incoming requests to.")
	flag.Parse()

	if *remote {
		log.Fatal(listenAndTunnel(tunneladdr))
	}

	for _, r := range ipranges {
		if err := parseAndAddCIDR(r); err == nil {
			continue
		}
		if err := parseAndAddIP(r); err == nil {
			continue
		}
		// TODO nmap-style octet addressing ip-range parsing.
		log.Fatalf("Couldn't parse address range %v", r)
	}

	addrpool.pool.OnEvicted = func(key lru.Key, value interface{}) {
		log.Printf("Evicting %s -> %v", uint32toip4(key.(uint32)), value.(string))
		addrpool.freeaddr = uint32toip4(key.(uint32))
		delete(addrpool.domains, value.(string))
	}

	for _, p := range listenports {
		go listenAndProxy(":" + p)
	}

	server := &dns.Server{
		Addr:    *dnsaddr,
		Net:     "udp",
		Handler: dns.HandlerFunc(resolver),
	}
	log.Fatal(server.ListenAndServe())
}
