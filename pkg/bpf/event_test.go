package bpf

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"lukechampine.com/blake3"
)

func TestHashFlow(t *testing.T) {

	h := blake3.New(8, nil)

	e := Event{
		SrcAddr:      net.ParseIP("1.2.3.4"),
		DstAddr:      net.ParseIP("5.6.7.8"),
		SrcPort:      1234,
		DstPort:      5678,
		Proto:        6,
		connectionID: 11111111,
	}

	e.hashFlow(h)

	assert.Equal(t, uint64(0x557151a9a4846ab8), e.FlowID)
}