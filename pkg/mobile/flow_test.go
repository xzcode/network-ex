package mobile

import (
	"encoding/binary"
	"github.com/xzcode/network-ex/internal/platform/packetqueue"
	"testing"
)

func TestFlowGenerationIsolation(t *testing.T) {
	d := packetqueue.New(nil, nil)
	s := &FlowSession{current: d, generation: 7}
	p := make([]byte, 20)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], 20)
	if s.PushPacket(p, 6) {
		t.Fatal("retired generation accepted")
	}
	if !s.PushPacket(p, 7) {
		t.Fatal("active generation rejected")
	}
	d.Close()
	if s.PushPacket(p, 7) {
		t.Fatal("closed generation accepted")
	}
	s.current = packetqueue.New(nil, nil)
	s.generation = 8
	defer s.current.Close()
	if s.PushPacket(p, 7) || !s.PushPacket(p, 8) {
		t.Fatal("generation transition not isolated")
	}
}
