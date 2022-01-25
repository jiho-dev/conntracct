package bpf

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"lukechampine.com/blake3"
)

var hashPool = sync.Pool{
	New: func() interface{} {
		// Output size is 32 bits.
		return blake3.New(4, nil)
	},
}

// EventLength is the length of the struct sent by BPF.
// power of 8
const EventLength = 96

var btime int64 = systemStart()

type IPv4Addr uint32

// 12 * uint64: 96 bytes
type CtEvent struct {
	Start       uint64 // epoch timestamp of flow start
	Stop        uint64
	Timestamp   uint64 // ktime of event, relative to machine boot time
	ConnPtr     uint64
	PacketsOrig uint64
	BytesOrig   uint64
	PacketsRet  uint64
	BytesRet    uint64
	SrcAddr     IPv4Addr
	DstAddr     IPv4Addr
	NatAddr     IPv4Addr
	Connmark    uint32
	NetNS       uint32
	SrcPort     uint16
	DstPort     uint16
	NatPort     uint16
	Zone        uint16
	Proto       uint8
	EventType   uint8
	TcpState    uint8
	Padding     uint8
}

type Event struct {
	CtEvent

	FlowID uint32
}

//////////////////////

const (
	EventTypeNone uint8 = iota
	EventTypeAdd
	EventTypeUpdate
	EventTypeDelete
)

var eventTypeString = map[uint8]string{
	EventTypeNone:   "None",
	EventTypeAdd:    "Add",
	EventTypeUpdate: "Update",
	EventTypeDelete: "Delete",
}

const (
	TcpCtNone uint8 = iota
	TcpCtSynSend
	TcpCtSynRecv
	TcpCtEstablish
	TcpCtFinWait
	TcpCtCloseWait
	TcpCtLastAck
	TcpCtTimeWait
	TcpCtClose
	TcpCtSyncSent2
)

var tcpStateString = map[uint8]string{
	TcpCtNone:      "NONE",
	TcpCtSynSend:   "SYN_SENT",
	TcpCtSynRecv:   "SYN_RECV",
	TcpCtEstablish: "ESTABLISHED",
	TcpCtFinWait:   "FIN_WAIT",
	TcpCtCloseWait: "CLOSE_WAIT",
	TcpCtLastAck:   "LAST_ACK",
	TcpCtTimeWait:  "TIME_WAIT",
	TcpCtClose:     "CLOSE",
	TcpCtSyncSent2: "SYN_SENT2",
}

var protoString = map[uint8]string{
	1:   "icmp",
	2:   "igmp",
	6:   "tcp",
	17:  "udp",
	33:  "dccp",
	47:  "gre",
	58:  "ipv6-icmp",
	94:  "ipip",
	115: "l2tp",
	132: "sctp",
	136: "udplite",
}

func getString(p uint8, s map[uint8]string) string {
	if val, ok := s[p]; ok {
		return val
	}

	return strconv.FormatUint(uint64(p), 10)
}

func GetProtocolString(p uint8) string {
	return getString(p, protoString)
}

func GetTcpStateString(p uint8) string {
	return getString(p, tcpStateString)
}

func GetEventTypeString(p uint8) string {
	return getString(p, eventTypeString)
}

////////////////////////////

func (e *Event) unmarshalBinary(b []byte) error {
	if len(b) != EventLength {
		return fmt.Errorf("input byte array incorrect length %d (expected %d)", len(b), EventLength)
	}

	e.CtEvent = *(*CtEvent)(unsafe.Pointer(&b[0]))

	e.SrcAddr = ntohl(e.SrcAddr)
	e.DstAddr = ntohl(e.DstAddr)
	e.NatAddr = ntohl(e.NatAddr)

	e.SrcPort = ntohs(e.SrcPort)
	e.DstPort = ntohs(e.DstPort)
	e.NatPort = ntohs(e.NatPort)

	// Generate and set the Event's FlowID.
	e.FlowID = e.hashFlow()

	return nil
}

// hashFlow calculates a flow hash base on the the Event's
// source and destination address, ports, protocol and connection ID.
func (e *Event) hashFlow() uint32 {

	// Get a Hasher from the pool.
	h := hashPool.Get().(*blake3.Hasher)

	// Source/Destination Address.
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(e.SrcAddr))
	_, _ = h.Write(b)
	binary.BigEndian.PutUint32(b, uint32(e.DstAddr))
	_, _ = h.Write(b)

	// Source Port.
	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, e.SrcPort)
	_, _ = h.Write(b)

	// Destination Port.
	binary.BigEndian.PutUint16(b, e.DstPort)
	_, _ = h.Write(b)

	// Protocol.
	_, _ = h.Write([]byte{e.Proto})

	// nf_conn struct kernel pointer.
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, e.ConnPtr)
	_, _ = h.Write(b)

	// Calculate the hash.
	// Shift one position to the right to fit the FlowID into a
	// signed integer field, eg. in elasticsearch.
	out := binary.LittleEndian.Uint32(h.Sum(nil)) >> 1

	// Reset and return the Hasher to the pool.
	h.Reset()
	hashPool.Put(h)

	return out
}

func systemStart() int64 {
	str, err := ioutil.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}

	lines := strings.Split(string(str), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "btime") {
			parts := strings.Split(line, " ")
			// format is btime 1388417200
			val, err := strconv.ParseInt(parts[1], 10, 32)
			if err != nil {
				return 0
			}

			return int64(val)
		}
	}

	return 0
}

/*
func jiffiesToTime(jiffies int64) time.Time {
	ticks, _ := sysconf.Sysconf(sysconf.SC_CLK_TCK)
	return time.Unix(btime+(jiffies/int64(ticks)), 0)
}

func jiffiesToDuration(jiffies int64) time.Duration {
	ticks, _ := sysconf.Sysconf(sysconf.SC_CLK_TCK)
	return time.Duration(jiffies / int64(ticks))
}
*/

// String returns a readable string representation of the Event.
func (e *Event) String() string {
	s := time.Unix(0, int64(e.Start))
	ts := time.Unix(btime, 0)
	ts = ts.Add(time.Duration(e.Timestamp))

	src := e.SrcAddr.String()
	dst := e.DstAddr.String()
	nat := e.NatAddr.String()

	return fmt.Sprintf("%s: %s, src=%s, dst=%s, nat=%s: %+v",
		GetEventTypeString(e.EventType), s,
		//ts,
		src, dst, nat,
		*e)
}

func (ipv4 *IPv4Addr) String() string {
	ipstr := fmt.Sprintf("%d.%d.%d.%d",
		*ipv4>>24,
		(*ipv4&0x00FFFFFF)>>16,
		(*ipv4&0x0000FFFF)>>8,
		*ipv4&0x000000FF)

	return ipstr
}

func ntohs(v uint16) uint16 {
	v1 := (v&0xFF)<<8 | (v&0xFF00)>>8
	return v1
}

func ntohl(v IPv4Addr) IPv4Addr {
	v1 := (v&0xFF)<<24 |
		(v&0xFF00)<<8 |
		(v&0xFF0000)>>8 |
		(v&0xFF000000)>>24

	return v1
}

// isIPv4 checks if everything but the first 4 bytes of a bytearray
// are zero. The nf_inet_addr C struct holds an IPv4 address in the
// first 4 bytes followed by zeroes. Does not execute a bounds check.
func isIPv4(s []byte) bool {
	for _, v := range s[4:] {
		if v != 0 {
			return false
		}
	}
	return true
}
