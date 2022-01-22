package bpf

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
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
const EventLength = 128

// Event is an accounting event delivered to userspace from the Probe.
type Event struct {
	Start       uint64 `json:"start"`     // epoch timestamp of flow start
	Timestamp   uint64 `json:"timestamp"` // ktime of event, relative to machine boot time
	FlowID      uint32 `json:"flow_id"`
	Connmark    uint32 `json:"connmark"`
	SrcAddr     net.IP `json:"src_addr"`
	DstAddr     net.IP `json:"dst_addr"`
	NatAddr     net.IP `json:"nat_addr"`
	PacketsOrig uint64 `json:"packets_orig"`
	BytesOrig   uint64 `json:"bytes_orig"`
	PacketsRet  uint64 `json:"packets_ret"`
	BytesRet    uint64 `json:"bytes_ret"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	NatPort     uint16 `json:"nat_port"`
	NetNS       uint32 `json:"netns"`
	Zone        uint16 `json:"zone"`
	Proto       uint8  `json:"proto"`
	EventType   uint8  `json:"event_type"`

	connPtr uint64
}

var EventTypeString = []string{"None", "Add", "Update", "Delete"}

// unmarshalBinary unmarshals a slice of bytes received from the
// kernel's eBPF perf map into a struct using the machine's native endianness.
func (e *Event) unmarshalBinary(b []byte) error {

	if len(b) != EventLength {
		return fmt.Errorf("input byte array incorrect length %d (expected %d)", len(b), EventLength)
	}

	e.Start = *(*uint64)(unsafe.Pointer(&b[0]))
	e.Timestamp = *(*uint64)(unsafe.Pointer(&b[8]))
	e.connPtr = *(*uint64)(unsafe.Pointer(&b[16]))

	// Build an IPv4 address if only the first four bytes
	// of the nf_inet_addr union are filled.
	// Assigning 4 bytes directly into IP() is incorrect,
	// an IPv4 is stored in the last 4 bytes of an IP().
	if isIPv4(b[24:40]) {
		e.SrcAddr = net.IPv4(b[24], b[25], b[26], b[27])
	} else {
		e.SrcAddr = net.IP(b[24:40])
	}

	if isIPv4(b[40:56]) {
		e.DstAddr = net.IPv4(b[40], b[41], b[42], b[43])
	} else {
		e.DstAddr = net.IP(b[40:56])
	}

	if isIPv4(b[56:72]) {
		e.NatAddr = net.IPv4(b[56], b[57], b[58], b[59])
	} else {
		e.NatAddr = net.IP(b[56:72])
	}

	e.PacketsOrig = *(*uint64)(unsafe.Pointer(&b[72]))
	e.BytesOrig = *(*uint64)(unsafe.Pointer(&b[80]))
	e.PacketsRet = *(*uint64)(unsafe.Pointer(&b[88]))
	e.BytesRet = *(*uint64)(unsafe.Pointer(&b[96]))

	e.Connmark = *(*uint32)(unsafe.Pointer(&b[104]))
	e.NetNS = *(*uint32)(unsafe.Pointer(&b[108]))

	// Only extract ports for UDP and TCP.
	e.Proto = b[120]
	if e.Proto == 6 || e.Proto == 17 {
		e.SrcPort = binary.BigEndian.Uint16(b[112:114])
		e.DstPort = binary.BigEndian.Uint16(b[114:116])
		e.NatPort = binary.BigEndian.Uint16(b[116:118])
	}
	//e.Zone = binary.BigEndian.Uint16(b[118:120])
	e.Zone = *(*uint16)(unsafe.Pointer(&b[118]))
	e.EventType = b[121]

	// Generate and set the Event's FlowID.
	//e.FlowID = e.hashFlow()

	return nil
}

// hashFlow calculates a flow hash base on the the Event's
// source and destination address, ports, protocol and connection ID.
func (e *Event) hashFlow() uint32 {

	// Get a Hasher from the pool.
	h := hashPool.Get().(*blake3.Hasher)

	// Source/Destination Address.
	_, _ = h.Write(e.SrcAddr)
	_, _ = h.Write(e.DstAddr)

	b := make([]byte, 2)

	// Source Port.
	binary.BigEndian.PutUint16(b, e.SrcPort)
	_, _ = h.Write(b)

	// Destination Port.
	binary.BigEndian.PutUint16(b, e.DstPort)
	_, _ = h.Write(b)

	// Protocol.
	_, _ = h.Write([]byte{e.Proto})

	// nf_conn struct kernel pointer.
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, e.connPtr)
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

var btime int64 = systemStart()

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

	return fmt.Sprintf("%s: %s(%s): %+v", EventTypeString[e.EventType], s, ts, *e)
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
