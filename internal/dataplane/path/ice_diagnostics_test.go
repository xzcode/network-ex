package path

import (
	"github.com/pion/ice/v4"
	"testing"
)

func TestICESnapshotDiagnostics(t *testing.T) {
	p := &ICE{}
	p.beginAttempt()
	p.candidate(true, ice.CandidateTypeHost)
	p.candidate(true, ice.CandidateTypeServerReflexive)
	p.candidate(false, ice.CandidateTypeServerReflexive)
	p.recordFailure("checking")
	p.clear()
	s := p.Snapshot()
	if s.State != "fallback" || s.LastFailure != "checking" || s.LocalHostCandidates != 1 || s.LocalReflexiveCandidates != 1 || s.RemoteReflexiveCandidates != 1 {
		t.Fatalf("unexpected diagnostic %+v", s)
	}
	p.beginAttempt()
	s = p.Snapshot()
	if s.LocalHostCandidates != 0 || s.RemoteReflexiveCandidates != 0 || s.LastFailure != "checking" {
		t.Fatal("stale candidate counts")
	}
	p.recordFailure("private-data")
	if p.Snapshot().LastFailure != "unknown" {
		t.Fatal("non-whitelisted phase")
	}
}
