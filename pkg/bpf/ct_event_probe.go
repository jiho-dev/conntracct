package bpf

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/ti-mo/conntracct/pkg/kernel"
	"github.com/ti-mo/conntracct/pkg/perf"
	"golang.org/x/sys/unix"
)

var (
	// `perf_raw_record` contains a trailing `u32 size`, whose length is
	// included in `perf_event_header.size`, the size of the record's buffer.
	// When reading raw perf samples from the ring, this many bytes need to be
	// popped from the end of the data to avoid returning garbage.
	perfRawRecordTailLength = 4
)

func init() {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	traceGroupSuffix = fmt.Sprintf("%x", b)
}

const perfCtEventMap = "perf_conntrack_event"

type EventHandler func(event *Event) bool

// Probe is an instance of a BPF probe running in the kernel.
type CtEventProbe struct {
	Handler EventHandler

	// cilium/ebpf resources.
	collection    *ebpf.Collection
	ctEventReader *perf.Reader

	// File descriptors of perf events opened for this probe.
	perfEventFds []int

	// Target kernel of the loaded probe.
	kernel kernel.Kernel

	// Channel for receiving IDs of lost perf events.
	lost chan uint64

	// Started status of the probe.
	startMu sync.Mutex
	started bool
}

// NewProbe instantiates a Probe using the given Config.
// Loads the BPF program into the kernel but does not attach its kprobes yet.
func NewCtEventProbe(cfg Config) (*CtEventProbe, error) {
	kr, err := kernelRelease()
	if err != nil {
		return nil, err
	}

	// Select the correct BPF probe from the library.
	br, k, err := Select(kr)
	if err != nil {
		return nil, errors.Wrap(err, "selecting probe version")
	}

	// Instantiate Probe with selected target kernel struct.
	ap := CtEventProbe{
		kernel: k,
	}

	// Scan kallsyms before attempting BPF load to avoid arcane error output from eBPF attach.
	if err := checkProbeKsyms(k.Probes); err != nil {
		return nil, err
	}

	if err := ap.load(br); err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("loading probe %s", k.Version))
	}

	// Apply probe configuration.
	if err := ap.configure(cfg); err != nil {
		return nil, errors.Wrap(err, "configuring probe")
	}

	return &ap, nil
}

func (ap *CtEventProbe) load(br *bytes.Reader) error {

	spec, err := ebpf.LoadCollectionSpecFromReader(br)
	if err != nil {
		return errors.Wrap(err, "loading collection spec")
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return errors.Wrap(err, "creating collection")
	}
	ap.collection = coll

	return nil
}

// closeTraceEvents closes all trace events (kprobe_events) of the Probe.
func (ap *CtEventProbe) closeTraceEvents() error {

	f, err := os.OpenFile(traceEventsPath, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("cannot open %s: %v", traceEventsPath, err)
	}
	defer f.Close()

	for _, p := range ap.kernel.Probes {
		pe := fmt.Sprintf("-:%s/%s", probeGroup(), probeName(p.Kind, p.Name))
		if _, err = f.WriteString(pe); err != nil {
			return fmt.Errorf("writing %q to kprobe_events: %v", pe, err)
		}
	}

	return nil
}

// perfEventOpenAttach creates a new perf event on tracepoint tid and binds a
// BPF program's progFd to it.
func (ap *CtEventProbe) perfEventOpenAttach(tid int, progFd int) error {

	attrs := &unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
		Config:      uint64(tid),
	}

	// Create a perf event that fires each time the given tracepoint
	// (kernel symbol) is hit.
	efd, err := unix.PerfEventOpen(attrs, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return fmt.Errorf("perf_event_open error: %v", err)
	}

	// Enable the perf event.
	if err := unix.IoctlSetInt(efd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		return fmt.Errorf("enabling perf event: %v", err)
	}

	// Set the BPF program to execute each time the perf event fires.
	if err := unix.IoctlSetInt(efd, unix.PERF_EVENT_IOC_SET_BPF, progFd); err != nil {
		return fmt.Errorf("attaching bpf program to perf event: %v", err)
	}

	// Store the FD for later teardown.
	ap.perfEventFds = append(ap.perfEventFds, efd)

	return nil
}

// perfEventDisable disables and closes all perf event efds stored in the Probe.
func (ap *CtEventProbe) disablePerfEvents() error {
	for _, efd := range ap.perfEventFds {
		if err := unix.IoctlSetInt(efd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
			return fmt.Errorf("disabling perf event: %v", err)
		}

		if err := unix.Close(efd); err != nil {
			return fmt.Errorf("closing perf event fd: %v", err)
		}
	}
	return nil
}

// Start attaches the BPF program's kprobes and starts polling the perf ring buffer.
func (ap *CtEventProbe) Start(useZeroCopy bool) error {

	ap.startMu.Lock()
	defer ap.startMu.Unlock()

	if ap.started {
		return errProbeStarted
	}

	for _, p := range ap.kernel.Probes {
		// Open a trace event for each of the kernel symbols we want to hook.
		// These events can be routed to the perf subsystem, where BPF programs
		// can be attached to them.
		tid, err := openTraceEvent(probeGroup(), p.Kind, p.Name)
		if err != nil {
			return err
		}

		prog, ok := ap.collection.Programs[p.ProgramName()]
		if !ok {
			return fmt.Errorf("looking up program '%s' in BPF collection", p.ProgramName())
		}

		// Create a perf event using the trace event opened above, and attach
		// a BPF program to it.
		if err := ap.perfEventOpenAttach(tid, prog.FD()); err != nil {
			return fmt.Errorf("opening perf event: %v", err)
		}
	}

	ap.lost = make(chan uint64)

	// Set up Readers for reading events from the perf ring buffers.
	r, err := perf.NewReader(ap.collection.Maps[perfCtEventMap], 4096)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("NewReader for %s", perfCtEventMap))
	}
	ap.ctEventReader = r

	// Start event decoder/fanout workers.
	go ap.ctEventWorker(useZeroCopy)

	ap.started = true

	return nil
}

// Stop stops the BPF program and releases all its related resources.
// Closes all Probe's channels. Can only be called after Start().
func (ap *CtEventProbe) Stop() error {
	ap.startMu.Lock()
	defer ap.startMu.Unlock()

	if !ap.started {
		return errProbeNotStarted
	}

	if ap.ctEventReader != nil {
		if err := ap.ctEventReader.Close(); err != nil {
			return err
		}
	}

	close(ap.lost)

	if err := ap.disablePerfEvents(); err != nil {
		return err
	}

	if err := ap.closeTraceEvents(); err != nil {
		return err
	}

	ap.collection.Close()

	return nil
}

// Kernel returns the target kernel structure of the selected probe.
func (ap *CtEventProbe) Kernel() kernel.Kernel {
	return ap.kernel
}

func (ap *CtEventProbe) trimTail(data []byte) []byte {
	l := len(data) - perfRawRecordTailLength
	return data[:l]
}

// ctEventWorker reads binady flow update events from the Probe's ring buffer,
// unmarshals the events into Event structures and sends them on all registered
// consumers' event channels.
func (ap *CtEventProbe) ctEventWorker(useZeroCopy bool) {
	var rec perf.Record
	_ = rec
	var err error
	var ae Event

	for {
		ae.Start = 0
		ae.Timestamp = 0
		ae.FlowID = 0
		ae.Connmark = 0

		if useZeroCopy {
			err = ap.ctEventReader.ZeroCopyRead(&rec)
		} else {
			rec, err = ap.ctEventReader.Read()
		}
		if err != nil {
			// Reader closed, gracefully exit the read loop.
			if perf.IsClosed(err) {
				return
			}

			fmt.Printf("unexpected error reading from ctEventReader:", err)
			continue
		}

		// Log the amount of lost samples and skip processing the sample.
		if rec.LostSamples > 0 {
			//ap.stats.incrPerfEventsUpdateLost(rec.LostSamples)

			// Done using the buffer
			ap.ctEventReader.PutTail(rec.Ring)
			continue
		}

		//ap.stats.incrPerfEventsUpdate()

		buf := ap.trimTail(rec.RawSample)
		if err = ae.unmarshalBinary(buf); err != nil {
			fmt.Printf("Err: %s \n", err)
		}

		if useZeroCopy {
			// Done using the buffer
			ap.ctEventReader.PutTail(rec.Ring)
		}

		if ae.Start != 0 && ap.Handler != nil {
			ap.Handler(&ae)
		}
	}
}

// configure sets configuration values in the probe's config map.
func (ap *CtEventProbe) configure(cfg Config) error {

	if ap.collection == nil {
		panic("nil eBPF collection in probe")
	}

	// Set sane defaults on the configuration structure.
	cfg.probeDefaults()

	if err := probeConfigVerify(cfg); err != nil {
		return errors.Wrap(err, "verifying probe configuration")
	}

	configMap, ok := ap.collection.Maps["config"]
	if !ok {
		return errors.New("map 'config' not found in eBPF collection")
	}

	curveMap, ok := ap.collection.Maps["config_ratecurve"]
	if !ok {
		return errors.New("map 'config_ratecurve' not found in eBPF collection")
	}

	if err := curveMap.Put(curve0Age, cfg.Curve0.Age.Nanoseconds()); err != nil {
		return errors.Wrap(err, "Curve0Age in config_ratecurve")
	}

	if err := curveMap.Put(curve0Rate, cfg.Curve0.Rate.Nanoseconds()); err != nil {
		return errors.Wrap(err, "Curve0Rate in config_ratecurve")
	}

	if err := curveMap.Put(curve1Age, cfg.Curve1.Age.Nanoseconds()); err != nil {
		return errors.Wrap(err, "Curve1Age in config_ratecurve")
	}

	if err := curveMap.Put(curve1Rate, cfg.Curve1.Rate.Nanoseconds()); err != nil {
		return errors.Wrap(err, "Curve1Rate in config_ratecurve")
	}

	if err := curveMap.Put(curve2Age, cfg.Curve2.Age.Nanoseconds()); err != nil {
		return errors.Wrap(err, "Curve2Age in config_ratecurve")
	}

	if err := curveMap.Put(curve2Rate, cfg.Curve2.Rate.Nanoseconds()); err != nil {
		return errors.Wrap(err, "Curve2Rate in config_ratecurve")
	}

	// XXX: Set capture all traffic
	if err := configMap.Put(configCaptureAll, int64(1)); err != nil {
		return errors.Wrap(err, "configCaptureAll in config")
	}

	if err := configMap.Put(configCoolDown, int64(0)); err != nil {
		return errors.Wrap(err, "configCaptureAll in config")
	}

	// Set the ready bit in the probe's config map to make it start sending traffic.
	if err := configMap.Put(configReady, readyValue); err != nil {
		return errors.Wrap(err, "configReady in config")
	}

	return nil
}
