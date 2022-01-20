package epoll

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"sync"

	utils "github.com/ti-mo/conntracct/pkg/utils"
)

// see cilium-ebpf/internal/epoll

// Poller waits for readiness notifications from multiple file descriptors.
//
// The wait can be interrupted by calling Close.
type Poller struct {
	// mutexes protect the fields declared below them. If you need to
	// acquire both at once you must lock epollMu before eventMu.
	epollMu sync.Mutex
	epollFd int

	eventMu sync.Mutex
	event   *eventFd
}

func New() (*Poller, error) {
	epollFd, err := utils.EpollCreate1(utils.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("create epoll fd: %v", err)
	}

	p := &Poller{epollFd: epollFd}
	p.event, err = newEventFd()
	if err != nil {
		utils.Close(epollFd)
		return nil, err
	}

	if err := p.Add(p.event.raw, 0); err != nil {
		utils.Close(epollFd)
		p.event.close()
		return nil, fmt.Errorf("add eventfd: %w", err)
	}

	runtime.SetFinalizer(p, (*Poller).Close)
	return p, nil
}

// Close the poller.
//
// Interrupts any calls to Wait. Multiple calls to Close are valid, but subsequent
// calls will return os.ErrClosed.
func (p *Poller) Close() error {
	runtime.SetFinalizer(p, nil)

	// Interrupt Wait() via the event fd if it's currently blocked.
	if err := p.wakeWait(); err != nil {
		return err
	}

	// Acquire the lock. This ensures that Wait isn't running.
	p.epollMu.Lock()
	defer p.epollMu.Unlock()

	// Prevent other calls to Close().
	p.eventMu.Lock()
	defer p.eventMu.Unlock()

	if p.epollFd != -1 {
		utils.Close(p.epollFd)
		p.epollFd = -1
	}

	if p.event != nil {
		p.event.close()
		p.event = nil
	}

	return nil
}

// Add an fd to the poller.
//
// id is returned by Wait in the utils.EpollEvent.Pad field any may be zero. It
// must not exceed math.MaxInt32.
//
// Add is blocked by Wait.
func (p *Poller) Add(fd int, id int) error {
	if int64(id) > math.MaxInt32 {
		return fmt.Errorf("unsupported id: %d", id)
	}

	p.epollMu.Lock()
	defer p.epollMu.Unlock()

	if p.epollFd == -1 {
		return fmt.Errorf("epoll add: %w", os.ErrClosed)
	}

	// The representation of EpollEvent isn't entirely accurate.
	// Pad is fully useable, not just padding. Hence we stuff the
	// id in there, which allows us to identify the event later (e.g.,
	// in case of perf events, which CPU sent it).
	event := utils.EpollEvent{
		Events: utils.EPOLLIN,
		Fd:     int32(fd),
		Pad:    int32(id),
	}

	if err := utils.EpollCtl(p.epollFd, utils.EPOLL_CTL_ADD, fd, &event); err != nil {
		return fmt.Errorf("add fd to epoll: %v", err)
	}

	return nil
}

// Wait for events.
//
// Returns the number of pending events or an error wrapping os.ErrClosed if
// Close is called.
func (p *Poller) Wait(events []utils.EpollEvent) (int, error) {
	p.epollMu.Lock()
	defer p.epollMu.Unlock()

	if p.epollFd == -1 {
		return 0, fmt.Errorf("epoll wait: %w", os.ErrClosed)
	}

	for {
		n, err := utils.EpollWait(p.epollFd, events, -1)
		if temp, ok := err.(temporaryError); ok && temp.Temporary() {
			// Retry the syscall if we were interrupted, see https://github.com/golang/go/issues/20400
			continue
		}

		if err != nil {
			return 0, err
		}

		for _, event := range events[:n] {
			if int(event.Fd) == p.event.raw {
				// Since we don't read p.event the event is never cleared and
				// we'll keep getting this wakeup until Close() acquires the
				// lock and sets p.epollFd = -1.
				return 0, fmt.Errorf("epoll wait: %w", os.ErrClosed)
			}
		}

		return n, nil
	}
}

type temporaryError interface {
	Temporary() bool
}

// waitWait unblocks Wait if it's epoll_wait.
func (p *Poller) wakeWait() error {
	p.eventMu.Lock()
	defer p.eventMu.Unlock()

	if p.event == nil {
		return fmt.Errorf("epoll wake: %w", os.ErrClosed)
	}

	return p.event.add(1)
}

// eventFd wraps a Linux eventfd.
//
// An eventfd acts like a counter: writes add to the counter, reads retrieve
// the counter and reset it to zero. Reads also block if the counter is zero.
//
// See man 2 eventfd.
type eventFd struct {
	file *os.File
	// prefer raw over file.Fd(), since the latter puts the file into blocking
	// mode.
	raw int
}

func newEventFd() (*eventFd, error) {
	fd, err := utils.Eventfd(0, utils.O_CLOEXEC|utils.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "event")
	return &eventFd{file, fd}, nil
}

func (efd *eventFd) close() error {
	return efd.file.Close()
}

func (efd *eventFd) add(n uint64) error {
	var buf [8]byte
	utils.NativeEndian.PutUint64(buf[:], 1)
	_, err := efd.file.Write(buf[:])
	return err
}

func (efd *eventFd) read() (uint64, error) {
	var buf [8]byte
	_, err := efd.file.Read(buf[:])
	return utils.NativeEndian.Uint64(buf[:]), err
}
