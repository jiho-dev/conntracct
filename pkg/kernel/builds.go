package kernel

// Builds is a list of Kernels that can be built against. We try to stick to one version
// per minor release. (eg 4.9.x)
//
// Whenever a breaking change is made to any of the structures the bpf program references,
// this map needs to be updated with the version it's introduced in.
var Builds = map[string]Kernel{
	// use vanilla kernel instead of CentOS 8.3 kernel
	// if compile error
	/*
		"4.18.0": {
			Version: "4.18.0",
			URL:     "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.18.1.tar.xz",
			Probes:  kprobes["acct_v1"],
			Params:  params["MarkNFTNat"],
		},
	*/

	//////////////////////////
	// CentOS 8.3(8.5) kernel
	"4.18.0": {
		Version:     "4.18.0",
		URL:         "file://pkg/kernel/source/linux-4.18.0-348.7.1.el8_5.tar.xz",
		ConfigFile:  "/pkg/kernel/source/config-4.18.0-348.7.1.el8_5.x86_64",
		BuildParams: []string{},
		Probes:      kprobes["acct_v1"],
	},

	// CentOS 7.3 kernel
	"3.10.0": {
		Version:    "3.10.0",
		URL:        "file://pkg/kernel/source/linux-3.10.0-1127.el7.tar.xz",
		ConfigFile: "/pkg/kernel/source/config-3.10.0-1127.el7.x86_64",
		BuildParams: []string{
			"-D_LINUX_3_10",
			"-Wno-error=unused-function",
		},
		Probes: kprobes["acct_v1"],
	},

	// Ubuntu 20.04 LTS
	"5.4.0": {
		Version:     "5.4.0",
		URL:         "file://pkg/kernel/source/linux-source-5.4.0.tar.bz2",
		ConfigFile:  "/pkg/kernel/source/config-5.4.0-84-generic",
		BuildParams: []string{},
		Probes:      kprobes["acct_v1"],
	},
}

var params = map[string]Params{
	"MarkNFTNat": {
		"CONFIG_NETFILTER":          "y",
		"CONFIG_NETFILTER_ADVANCED": "y",

		"CONFIG_NF_CONNTRACK":      "m",
		"CONFIG_NF_CONNTRACK_MARK": "y",

		// Changes alignment of the ct extensions enum for timestamp.
		"CONFIG_NF_NAT":                 "m",
		"CONFIG_NF_CONNTRACK_EVENTS":    "y",
		"CONFIG_NF_CONNTRACK_TIMESTAMP": "y",

		"CONFIG_NF_TABLES": "m",
		"CONFIG_NFT_NAT":   "m",

		// Disabling SMP makes some structs smaller by removing some
		// synchronization primitives.
		"CONFIG_SMP": "y",
	},
}

var kprobes = map[string]Probes{
	// These probes are enabled in the sequence listed here.
	// List functions that insert records into a map last to prevent stale records in BPF maps.
	"acct_v1": {
		{
			Kind: "kprobe",
			Name: "nf_ct_delete",
		},
		{
			Kind: "kretprobe",
			Name: "__nf_ct_refresh_acct",
		},
		{
			Kind: "kprobe",
			Name: "__nf_ct_refresh_acct",
		},
		{
			Kind: "kprobe",
			Name: "__nf_conntrack_hash_insert",
		},
	},
}
