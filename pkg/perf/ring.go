package perf

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/ti-mo/conntracct/pkg/utils"
)

// see cilium-ebpf/perf

// perfEventRing is a page of metadata followed by
// a variable number of pages which form a ring buffer.
type perfEventRing struct {
	fd   int
	cpu  int
	mmap []byte
	*ringReader
}

func newPerfEventRing(cpu, perCPUBuffer, watermark int) (*perfEventRing, error) {
	if watermark >= perCPUBuffer {
		return nil, errors.New("watermark must be smaller than perCPUBuffer")
	}

	fd, err := createPerfEvent(cpu, watermark)
	if err != nil {
		return nil, err
	}

	if err := utils.SetNonblock(fd, true); err != nil {
		utils.Close(fd)
		return nil, err
	}

	mmap, err := utils.Mmap(fd, 0, perfBufferSize(perCPUBuffer), utils.PROT_READ|utils.PROT_WRITE, utils.MAP_SHARED)
	if err != nil {
		utils.Close(fd)
		return nil, fmt.Errorf("can't mmap: %v", err)
	}

	// This relies on the fact that we allocate an extra metadata page,
	// and that the struct is smaller than an OS page.
	// This use of unsafe.Pointer isn't explicitly sanctioned by the
	// documentation, since a byte is smaller than sampledPerfEvent.
	meta := (*utils.PerfEventMmapPage)(unsafe.Pointer(&mmap[0]))

	ring := &perfEventRing{
		fd:         fd,
		cpu:        cpu,
		mmap:       mmap,
		ringReader: newRingReader(meta, mmap[meta.Data_offset:meta.Data_offset+meta.Data_size]),
	}
	runtime.SetFinalizer(ring, (*perfEventRing).Close)

	return ring, nil
}

// mmapBufferSize returns a valid mmap buffer size for use with perf_event_open (1+2^n pages)
func perfBufferSize(perCPUBuffer int) int {
	pageSize := os.Getpagesize()

	// Smallest whole number of pages
	nPages := (perCPUBuffer + pageSize - 1) / pageSize

	// Round up to nearest power of two number of pages
	nPages = int(math.Pow(2, math.Ceil(math.Log2(float64(nPages)))))

	// Add one for metadata
	nPages += 1

	return nPages * pageSize
}

func (ring *perfEventRing) Close() {
	runtime.SetFinalizer(ring, nil)

	_ = utils.Close(ring.fd)
	_ = utils.Munmap(ring.mmap)

	ring.fd = -1
	ring.mmap = nil
}

func createPerfEvent(cpu, watermark int) (int, error) {
	if watermark == 0 {
		watermark = 1
	}

	attr := utils.PerfEventAttr{
		Type:        utils.PERF_TYPE_SOFTWARE,
		Config:      utils.PERF_COUNT_SW_BPF_OUTPUT,
		Bits:        utils.PerfBitWatermark,
		Sample_type: utils.PERF_SAMPLE_RAW,
		Wakeup:      uint32(watermark),
	}

	attr.Size = uint32(unsafe.Sizeof(attr))
	fd, err := utils.PerfEventOpen(&attr, -1, cpu, -1, utils.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("can't create perf event: %w", err)
	}
	return fd, nil
}

type ringReader struct {
	meta       *utils.PerfEventMmapPage
	head, tail uint64
	mask       uint64
	ring       []byte
}

func newRingReader(meta *utils.PerfEventMmapPage, ring []byte) *ringReader {
	return &ringReader{
		meta: meta,
		head: atomic.LoadUint64(&meta.Data_head),
		tail: atomic.LoadUint64(&meta.Data_tail),
		// cap is always a power of two
		mask: uint64(cap(ring) - 1),
		ring: ring,
	}
}

func (rr *ringReader) loadHead() {
	rr.head = atomic.LoadUint64(&rr.meta.Data_head)
}

func (rr *ringReader) writeTail() {
	// Commit the new tail. This lets the kernel know that
	// the ring buffer has been consumed.
	atomic.StoreUint64(&rr.meta.Data_tail, rr.tail)
}

func (rr *ringReader) Read(p []byte) (int, error) {
	start := int(rr.tail & rr.mask)

	n := len(p)
	// Truncate if the read wraps in the ring buffer
	if remainder := cap(rr.ring) - start; n > remainder {
		n = remainder
	}

	// Truncate if there isn't enough data
	if remainder := int(rr.head - rr.tail); n > remainder {
		n = remainder
	}

	copy(p, rr.ring[start:start+n])
	rr.tail += uint64(n)

	if rr.tail == rr.head {
		return n, io.EOF
	}

	return n, nil
}

func (rr *ringReader) getTailRingBuffer(n int) ([]byte, error) {
	start := int(rr.tail & rr.mask)

	// Truncate if the read wraps in the ring buffer
	if remainder := cap(rr.ring) - start; n > remainder {
		n = remainder
	}

	// Truncate if there isn't enough data
	if remainder := int(rr.head - rr.tail); n > remainder {
		n = remainder
	}

	b := rr.ring[start : start+n]
	rr.tail += uint64(n)

	if rr.tail == rr.head {
		return b, io.EOF
	}

	return b, nil
}

func (rr *ringReader) ZeroCopyReadRing(size int) ([]byte, error) {
	var nTotal int = 0
	var err error
	var chunk [][]byte

	for nTotal < size && err == nil {
		data, err := rr.getTailRingBuffer(size - nTotal)

		r := len(data)
		if r > 0 {
			chunk = append(chunk, data)
			nTotal += r
		}

		if nTotal < size && err == io.EOF {
			err = errEOR
		} else {
			err = nil
		}
	}

	// if data chunk
	// copy them to single buffer
	if len(chunk) > 1 {
		data := make([]byte, nTotal)

		var l int
		for _, c := range chunk {
			copy(data[l:], c)
			l += len(c)
		}

		return data, err
	}

	return chunk[0], err
}
