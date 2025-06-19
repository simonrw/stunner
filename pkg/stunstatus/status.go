package stunstatus

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	math "math/rand"
	"net"
	"net/http"
	"time"

	"github.com/jackpal/gateway"
	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
)

const (
	Blocked                        = "UDP Blocked"
	OpenInternet                   = "No NAT"
	EndpointIndependentMapping     = "Endpoint-Independent Mapping"
	AddressDependentFiltering      = "Address-Dependent Filtering"
	AddressDependentMapping        = "Address-Dependent Mapping"
	AddressAndPortDependentMapping = "Address and Port-Dependent Mapping"
	ChangedAddressError            = "ChangedAddressError"
)

const (
	attrSoftware    = 0x8022 // STUN attribute for software
	attrFingerprint = 0x8028 // STUN attribute for fingerprint
)

var (
	bindingRequestType = []byte{0x00, 0x01}
	magicCookie        = []byte{0x21, 0x12, 0xA4, 0x42} // defined by RFC 5389
)

type TxID [12]byte
type PerServerResult struct {
	Server          string
	NATType         string
	ExternalIP      string
	ExternalPort    int
	MappingProtocol string
}

type STUNOptions struct {
	StunServers []string
	SourcePort  int
	SourceIP    string
	Software    string
	DerpMapUrl  string
	STUNPort    int
}

type STUNResults struct {
	Results  []PerServerResult
	FinalNAT string
}

type RetVal struct {
	Resp         bool   // did we get a response?
	ExternalIP   string // what IP did the STUN server see
	ExternalPort int    // what port did the STUN server see
	SourceIP     string // what IP did we bind to
	SourcePort   int    // what port did we bind to
	ChangedIP    string // what IP did the STUN server see after we sent a change request
	ChangedPort  int    // what port did the STUN server see after we sent a change request
}

func ComputeSTUNStatus(mc *STUNOptions) (*STUNResults, error) {
	if mc.DerpMapUrl == "" {
		mc.DerpMapUrl = "https://login.tailscale.com/derpmap/default"
	}
	if mc.STUNPort == 0 {
		mc.STUNPort = 3478
	}
	if mc.SourcePort == 0 {
		mc.SourcePort = randomPort()
	}

	if len(mc.StunServers) < 2 {
		var err error
		mc.StunServers, err = getStunServers(mc.DerpMapUrl, mc.STUNPort)
		if err != nil {
			return nil, fmt.Errorf("error fetching DERP map: %w", err)
		}
	}

	results, finalNAT, _, _ := multiServerDetection(mc.StunServers, mc.SourceIP, mc.SourcePort, mc.Software)

	mappingProtocol, err := probePortmapAvailability()
	if err != nil {
		return nil, fmt.Errorf("fetching portmap availablility: %w", err)
	}

	for i := range results {
		results[i].MappingProtocol = mappingProtocol
	}

	return &STUNResults{
		Results:  results,
		FinalNAT: finalNAT,
	}, nil

}

func probePortmapAvailability() (string, error) {
	// Attempt to discover default gateway
	if _, err := gateway.DiscoverGateway(); err != nil {
		return "", fmt.Errorf("discovering gateway: %w", err)
	}
	// logger.Debugf("gateway discovery returned: %v", gw)

	nm, err := netmon.New(func(string, ...any) {})
	if err != nil {
		return "", fmt.Errorf("netmon.New failed: %w", err)
	}
	nm.Start()

	defer nm.Close()

	pm := portmapper.NewClient(
		func(format string, args ...interface{}) {},
		nm, nil, nil,
		func() {},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	probeResult, err := pm.Probe(ctx)
	if err != nil {
		// logger.Debugf("pm.Probe => error: %v", err)
		return "None", nil
	}

	// If PCP is found, we label it "PCP".
	// If PMP is found, we label it "NAT-PMP".
	// If UPnP is found, we label it "UPnP".
	if probeResult.PCP {
		return "PCP", nil
	} else if probeResult.PMP {
		return "NAT-PMP", nil
	} else if probeResult.UPnP {
		return "UPnP", nil
	}
	return "None", nil
}

func multiServerDetection(servers []string, sourceIP string, sourcePort int, software string) ([]PerServerResult, string, string, int) {

	// bind to a local UDP socket on the specified source port
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(sourceIP), Port: sourcePort})
	if err != nil {
		// logger.Debugf("Bind error: %v", err)
		return nil, Blocked, "", 0 // we can't bind, so we assume blocked
	}
	defer sock.Close()

	_ = sock.SetDeadline(time.Now().Add(5 * time.Minute)) // set a deadline for the socket
	var results []PerServerResult
	allPorts := make(map[int]bool)

	// loop through the servers and try discover the NAT type
	// NOTE: a single request doesn't give us everything we need, so see finalizeNAT for the final answer
	for _, srv := range servers {
		// logger.Debugf("Do Test1 with server=%s", srv)
		natType, retVal := getNatType(sock, srv, software)

		// logger.Debugf("Result after Test1 server=%s => NAT=%s, IP=%s, Port=%d",
		// 	srv, natType, retVal.ExternalIP, retVal.ExternalPort)

		// We'll fill in MappingProtocol later, from probePortmapAvailability()
		results = append(results, PerServerResult{
			Server:       srv,
			NATType:      natType,
			ExternalIP:   retVal.ExternalIP,
			ExternalPort: retVal.ExternalPort,
		})
		if retVal.ExternalPort != 0 {
			allPorts[retVal.ExternalPort] = true
		}
	}

	finalN, finalIP, finalPort := finalizeNAT(results, allPorts)
	return results, finalN, finalIP, finalPort
}

func getNatType(sock *net.UDPConn, server string, software string) (string, RetVal) {
	ret := stunTest(sock, server, "", software)
	if !ret.Resp {
		return Blocked, ret
	}
	exIP, exPort := ret.ExternalIP, ret.ExternalPort
	chIP, chPort := ret.ChangedIP, ret.ChangedPort
	if exIP == "" {
		return Blocked, ret
	}

	localAddr := sock.LocalAddr().(*net.UDPAddr)
	if exIP == localAddr.IP.String() {
		ret2 := stunTest(sock, server, "00000006", software)
		if ret2.Resp {
			return OpenInternet, ret2
		}
		return AddressDependentFiltering, ret2
	}

	ret2 := stunTest(sock, server, "00000006", software)
	if ret2.Resp {
		return EndpointIndependentMapping, ret2
	}
	ret3 := stunTestToIP(sock, chIP, chPort, "", software)
	if !ret3.Resp {
		return ChangedAddressError, ret3
	}
	if exIP == ret3.ExternalIP && exPort == ret3.ExternalPort {
		ret4 := stunTestToIP(sock, chIP, chPort, "00000002", software)
		if ret4.Resp {
			return AddressDependentMapping, ret4
		}
		return AddressAndPortDependentMapping, ret4
	}
	return AddressAndPortDependentMapping, ret3
}

// Run a test1/test approach against a STUN server
// we send a request, then send a change request to determine if we get the same port/IP tuple
func stunTest(sock *net.UDPConn, hostPort, changeReq, software string) RetVal {
	var ret RetVal
	var tx TxID
	_, _ = rand.Read(tx[:])

	var crBytes []byte
	if changeReq != "" {
		crBytes, _ = hex.DecodeString(changeReq)
	}

	req := buildRequest(tx, software, crBytes)

	// logger.Debugf("TransactionID=%x, sending STUN request to %s with changeReq=%q", tx, hostPort, changeReq)

	count := 3
	for count > 0 {
		count--
		raddr, err := net.ResolveUDPAddr("udp", hostPort)
		if err != nil {
			// logger.Debugf("resolveUDPAddr error: %v", err)
			continue
		}

		// logger.Debugf("sendto: %s", hostPort)

		_, err = sock.WriteToUDP(req, raddr)
		if err != nil {
			// logger.Debugf("WriteToUDP error: %v", err)
			continue
		}

		buf := make([]byte, 2048)
		_ = sock.SetReadDeadline(time.Now().Add(2 * time.Second))

		n, _, err := sock.ReadFromUDP(buf)
		if err != nil {
			// logger.Debugf("readFromUDP error: %v, tries left=%d", err, count)
			continue
		}

		// logger.Debugf("recvfrom: %v, %d bytes", from, n)

		if n < 20 {
			// logger.Debug("received too few bytes, ignoring")
			continue
		}

		mt := binary.BigEndian.Uint16(buf[0:2])
		if mt != 0x0101 {
			// logger.Debugf("not a BindingSuccess => 0x%04x", mt)
			continue
		}

		cookie := buf[4:8]
		tid := buf[8:20]
		if !compareCookieAndTID(cookie, tid, tx) {
			// logger.Debug("TransactionID mismatch")
			continue
		}

		msgLen := binary.BigEndian.Uint16(buf[2:4])
		if int(msgLen) > (n - 20) {
			// logger.Debugf("message length too large: %d vs actual %d", msgLen, n-20)
			continue
		}

		attrData := buf[20 : 20+msgLen]
		ret.Resp = true
		parseSTUNAttributes(attrData, &ret)

		// logger.Debugf("Parsed STUN response => IP=%s Port=%d", ret.ExternalIP, ret.ExternalPort)
		return ret
	}
	return ret
}

func stunTestToIP(sock *net.UDPConn, ip string, port int, changeReq, software string) RetVal {
	if ip == "" || port == 0 {
		return RetVal{}
	}
	return stunTest(sock, fmt.Sprintf("%s:%d", ip, port), changeReq, software)
}

// look at the results we sent to the STUN servers and determine the NAT type
func finalizeNAT(results []PerServerResult, ports map[int]bool) (string, string, int) {
	allBlocked := true
	for _, r := range results {
		if r.NATType != Blocked {
			allBlocked = false
			break
		}
	}
	if allBlocked {
		return Blocked, "", 0
	}

	if len(ports) > 1 {
		for _, r := range results {
			if r.ExternalIP != "" {
				return AddressAndPortDependentMapping, r.ExternalIP, r.ExternalPort
			}
		}
		return AddressAndPortDependentMapping, "", 0
	}

	// NAT RFC mappings
	priority := map[string]int{
		OpenInternet:                   6,
		EndpointIndependentMapping:     5,
		AddressDependentMapping:        4,
		AddressAndPortDependentMapping: 3,
		AddressDependentFiltering:      2,
		Blocked:                        0,
		ChangedAddressError:            0,
	}
	bestType := Blocked
	bestScore := 0
	var bestIP string
	var bestPort int

	for _, r := range results {
		sc := priority[r.NATType]
		if sc > bestScore {
			bestScore = sc
			bestType = r.NATType
			bestIP = r.ExternalIP
			bestPort = r.ExternalPort
		}
	}
	return bestType, bestIP, bestPort
}

// build the STUN request with all of the attributes
// if we include the SOFTWARE attribute, it will be 0x8022
// 0x0003 => CHANGE-REQUEST
// 0x8028 => FINGERPRINT
// 0x0001 => MAPPED-ADDRESS
func buildRequest(tx TxID, software string, changeReq []byte) []byte {
	var attrs []byte
	if software != "" {
		sw := []byte(software)
		attrs = appendU16(attrs, attrSoftware)
		attrs = appendU16(attrs, uint16(len(sw)))
		attrs = append(attrs, sw...)
		attrs = stunPad(attrs)
	}
	if len(changeReq) == 4 {
		attrs = appendU16(attrs, 0x0003)
		attrs = appendU16(attrs, 4)
		attrs = append(attrs, changeReq...)
		attrs = stunPad(attrs)
	}
	hdr := make([]byte, 0, 20)
	hdr = append(hdr, bindingRequestType...)
	hdr = appendU16(hdr, 0)
	hdr = append(hdr, magicCookie...)
	hdr = append(hdr, tx[:]...)
	tmp := append(hdr, attrs...)
	fp := fingerPrint(tmp)
	fpA := make([]byte, 0, 8)
	fpA = appendU16(fpA, attrFingerprint)
	fpA = appendU16(fpA, 4)
	fpA = appendU32(fpA, fp)
	out := append(tmp, fpA...)
	attrLen := len(out) - 20
	binary.BigEndian.PutUint16(out[2:4], uint16(attrLen))
	return out
}

func compareCookieAndTID(cookie, tid []byte, tx TxID) bool {
	if len(cookie) != 4 || len(tid) != 12 {
		return false
	}
	if cookie[0] != 0x21 || cookie[1] != 0x12 || cookie[2] != 0xa4 || cookie[3] != 0x42 {
		return false
	}
	return string(tid) == string(tx[:])
}

// Checks whether the first 4 bytes are the correct STUN magic cookie, and whether the next 12 bytes match our transaction ID.
func fingerPrint(b []byte) uint32 {
	c := crc32.ChecksumIEEE(b)
	return c ^ 0x5354554e
}

// Computes the STUN FINGERPRINT by taking the CRC32-IEEE of the packet data and XORing with 0x5354554e, per RFC5389.
func stunPad(b []byte) []byte {
	p := (4 - (len(b) % 4)) % 4
	if p == 0 {
		return b
	}
	return append(b, make([]byte, p)...)
}

// helper function for appending a 16-bit unsigned integer to a byte slice
func appendU16(b []byte, v uint16) []byte {
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], v)
	return append(b, tmp[:]...)
}

// helper function for appending a 32-bit unsigned integer to a byte slice
func appendU32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

type NatDetail struct {
	EasyVsHard string
	Notes      string
}

func NatDetailFor(n string) NatDetail {
	switch n {
	case Blocked:
		return NatDetail{"Hard", "The NAT or firewall is preventing inbound hole-punch attempts. Outbound connections do not facilitate inbound reachability."}
	case OpenInternet:
		return NatDetail{"Easy", "Your host is directly reachable from the internet."}
	case EndpointIndependentMapping:
		return NatDetail{"Easy", "Reuses the same public port for all remote connections, enabling inbound hole punching from any peer once an outbound packet is sent."}
	case AddressDependentFiltering:
		return NatDetail{"Hard", "Incoming packets are only accepted from the same remote IP that was used in the initial outbound connection, limiting who can punch in."}
	case AddressDependentMapping:
		return NatDetail{"Easy", "Uses one public port for each remote IP. Inbound connections must come from that IP."}
	case AddressAndPortDependentMapping:
		return NatDetail{"Hard", "Allocates different public ports for each remote IP:port combination, making inbound hole punching very difficult."}
	case ChangedAddressError:
		return NatDetail{"N/A", "An error occurred during NAT detection preventing a full classification."}
	default:
		return NatDetail{"N/A", "Unknown NAT type - no conclusive classification could be determined from the tests."}
	}
}

// parseSTUNAttributes parses the STUN attributes from the response
// 0x0001 => MAPPED-ADDRESS
// 0x0005 => CHANGED-ADDRESS
// 0x0020 => XOR-MAPPED-ADDRESS
func parseSTUNAttributes(attrs []byte, ret *RetVal) {
	var offset int
	for offset+4 <= len(attrs) {
		aType := binary.BigEndian.Uint16(attrs[offset : offset+2])
		aLen := binary.BigEndian.Uint16(attrs[offset+2 : offset+4])
		end := offset + 4 + int(aLen)
		if end > len(attrs) {
			break
		}
		val := attrs[offset+4 : end]
		switch aType {
		case 0x0001:
			if len(val) >= 8 {
				p := int(val[2])<<8 | int(val[3])
				ip4 := fmt.Sprintf("%d.%d.%d.%d", val[4], val[5], val[6], val[7])
				ret.ExternalIP = ip4
				ret.ExternalPort = p
			}
		case 0x0005:
			if len(val) >= 8 {
				p := int(val[2])<<8 | int(val[3])
				ip4 := fmt.Sprintf("%d.%d.%d.%d", val[4], val[5], val[6], val[7])
				ret.ChangedIP = ip4
				ret.ChangedPort = p
			}
		case 0x0020:
			if len(val) >= 8 {
				const mc = 0x2112A442
				p := binary.BigEndian.Uint16(val[2:4]) ^ uint16(mc>>16)
				raw := binary.BigEndian.Uint32(val[4:8]) ^ mc
				ip := make(net.IP, 4)
				binary.BigEndian.PutUint32(ip, raw)
				ret.ExternalIP = ip.String()
				ret.ExternalPort = int(p)
			}
		}
		offset = end
	}
}

// derpMap is the JSON structure returned by https://login.tailscale.com/derpmap/default.
type derpMap struct {
	Regions map[string]struct {
		Nodes []struct {
			HostName string `json:"HostName"`
		} `json:"Nodes"`
	} `json:"Regions"`
}

func getStunServers(derpMapURL string, port int) ([]string, error) {
	resp, err := http.Get(derpMapURL)
	if err != nil {
		return nil, fmt.Errorf("fetching DERP map: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d from DERP map", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading DERP map response: %w", err)
	}

	var dm derpMap
	if err := json.Unmarshal(body, &dm); err != nil {
		return nil, fmt.Errorf("decoding DERP map JSON: %w", err)
	}

	var all []string
	for _, region := range dm.Regions {
		for _, node := range region.Nodes {
			if node.HostName != "" {
				all = append(all, node.HostName)
			}
		}
	}
	if len(all) < 2 {
		return nil, fmt.Errorf("found only %d DERP servers in map, need at least 2", len(all))
	}
	math.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })

	for i := range all {
		all[i] = fmt.Sprintf("%s:%d", all[i], port)
	}
	// logger.Debug("Using DERP servers: ", all[:2])
	return all[:2], nil
}

// generate a random port in the range 49152-65535
func randomPort() int {
	return 49152 + math.Intn(16384)
}
