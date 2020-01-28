package bpf

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashFlow(t *testing.T) {

	e := Event{
		SrcAddr:      net.ParseIP("1.2.3.4"),
		DstAddr:      net.ParseIP("5.6.7.8"),
		SrcPort:      1234,
		DstPort:      5678,
		Proto:        6,
		connectionID: 11111111,
	}

	assert.Equal(t, uint32(0x24846ab8), e.hashFlow())
}
