package pipeline

import (
	log "github.com/sirupsen/logrus"

	"gitlab.com/0ptr/conntracct/pkg/bpf"
)

// RunAcct starts collecting conntrack accounting data
// from the local Linux host.
func (p *Pipeline) RunAcct() error {

	if p.acctModule != nil {
		return errAcctAlreadyInitialized
	}

	mod, aec, ael, err := bpf.Init()
	if err != nil {
		log.Fatalln("Error initializing acct infrastructure:", err)
	}

	// Save the elf module to ingest object
	p.acctModule = mod

	go p.acctEventWorker(aec)

	go func() {
		for {
			ae, ok := <-ael
			if !ok {
				log.Info("BPF lost channel closed, exiting read loop")
				break
			}

			log.Errorf("Dropped BPF event '%v', possible congestion", ae)
		}
	}()

	log.Info("Started BPF accounting infrastructure")

	return nil
}

// acctEventWorker receives from a bpf.AcctEvent channel
// and delivers to all AcctEvent sinks registered to the pipeline.
func (p *Pipeline) acctEventWorker(aec chan bpf.AcctEvent) {
	for {

		ae, ok := <-aec
		if !ok {
			log.Info("AcctEvent channel closed, stopping acctEventWorker")
			break
		}

		// Save last-received perf count to ingest object
		// TODO: Make thread-safe
		p.Stats.AcctPerfEvents = ae.EventID
		p.Stats.AcctPerfBytes = ae.EventID * bpf.AcctEventLength
		p.Stats.AcctEventQueueLen = len(aec)

		// TODO: Publish to AcctEvent sinks
	}
}
