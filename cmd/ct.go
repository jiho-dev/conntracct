package cmd

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/ti-mo/conntracct/pkg/bpf"
	"github.com/ti-mo/conntracct/pkg/config"

	// side effect of registering HTTP handler in default ServeMux
	_ "net/http/pprof" //nolint:gosec
)

// runCmd represents the run command.
var ctCmd = &cobra.Command{
	Use:          "ct",
	Short:        "Listen for conntrack events and send them to configured sinks.",
	RunE:         ctCmdRun,
	SilenceUsage: true, // Don't show usage when RunE returns error.
}

var evCount int

func init() {
	rootCmd.AddCommand(ctCmd)
}

func ReceiveEvent(event *bpf.Event) bool {
	perCnt := 1000

	evCount++

	if event != nil && (evCount%perCnt) == 1 {
		//s := time.Now().Format("2006-01-02 15:04:05")
		//fmt.Println(s) // 2019-01-12 10:20:30
		log.Printf("idx=%d %+v", evCount, event.String())
	}

	return true
}

func ctCmdRun(cmd *cobra.Command, args []string) error {
	addr := "0.0.0.0:6060"
	log.Printf("Starting pporf: %s \n", addr)
	ListenAndServe(addr)

	log.Printf("Starting \n")

	// Get probe configuration from Viper.
	//pcfg, err := config.DecodeProbeConfigMap(viper.GetStringMap(cfgProbe))

	pcfg, err := config.DecodeProbeConfigMap(nil)
	if err != nil {
		return nil
	}

	log.Printf("Read probe configuration: %+v ", pcfg)

	// Fill ProbeConfig with defaults.
	pcfg.Default(config.DefaultProbeConfig)
	log.Printf("Using probe configuration: %+v", pcfg)

	//////////////////////
	// Extract BPF configuration from app configuration.
	cfg := pcfg.BPFConfig()
	log.Printf("Using BPF cfg: %+v", cfg)

	// Create a new accounting probe.
	ap, err := bpf.NewCtEventProbe(cfg)
	if err != nil {
		log.Printf("failed to initialize BPF probe, %s", err)
		return nil
	}
	ap.Handler = ReceiveEvent

	log.Printf("Inserted probe version %s", ap.Kernel().Version)

	// Start the Probe.
	if err := ap.Start(true); err != nil {
		if strings.Contains(err.Error(), "kprobe_events") {
			log.Printf("Either another conntracct instance is running, or the program was sent a SIGKILL. Try running 'echo | sudo tee /sys/kernel/debug/tracing/kprobe_events'. (will detach all kprobes)")
		}

		return errors.Wrap(err, "starting probe")
	}

	log.Printf("Started accounting probe and workers")

	// Wait for program to be interrupted.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	log.Printf("Exiting with signal: %+v ", <-sig)

	return nil
}

// ListenAndServe starts a pprof endpoint on the given addr
// and replaces the global http.DefaultServeMux with a new instance.
func ListenAndServe(addr string) {

	// Save a reference to the default global ServeMux.
	ppm := http.DefaultServeMux

	// Replace the default ServeMux with a new instance.
	http.DefaultServeMux = http.NewServeMux()

	// Start pprof server on global ServeMux.
	go func() {
		log.Fatal(http.ListenAndServe(addr, ppm))
	}()
}
