package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pion/stun"
	"github.com/xzcode/network-ex/internal/dataplane/relay"
	"github.com/xzcode/network-ex/pkg/protocol"
)

const schemaV2 = `
CREATE TABLE relay_nodes(id TEXT PRIMARY KEY, region TEXT NOT NULL, relay_url TEXT NOT NULL UNIQUE, stun_url TEXT NOT NULL, network_id TEXT REFERENCES networks(id), identity TEXT UNIQUE, invite_hash TEXT, invite_expires INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','draining','revoked')), priority INTEGER NOT NULL, max_connections INTEGER NOT NULL, bytes_per_second INTEGER NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0, connections INTEGER NOT NULL DEFAULT 0, ingress INTEGER NOT NULL DEFAULT 0, egress INTEGER NOT NULL DEFAULT 0, dropped INTEGER NOT NULL DEFAULT 0);
CREATE TABLE node_nonces(node_id TEXT NOT NULL REFERENCES relay_nodes(id), nonce TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(node_id,nonce));
CREATE TABLE node_probes(device_id TEXT NOT NULL REFERENCES devices(id), node_id TEXT NOT NULL REFERENCES relay_nodes(id), rtt INTEGER NOT NULL, failures INTEGER NOT NULL, observed INTEGER NOT NULL, PRIMARY KEY(device_id,node_id));
CREATE TABLE pair_relays(network_id TEXT NOT NULL REFERENCES networks(id), a TEXT NOT NULL REFERENCES devices(id), b TEXT NOT NULL REFERENCES devices(id), node_id TEXT NOT NULL, changed INTEGER NOT NULL, PRIMARY KEY(network_id,a,b), CHECK(a<b));
CREATE INDEX idx_pair_relays_node ON pair_relays(node_id);
CREATE INDEX idx_node_nonces_expiry ON node_nonces(expires);
PRAGMA user_version=2;
`
const heartbeatTTL = 12
const probeTTL = 20
const maxNodes = 16

var nodeID = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$")

type NodeView struct {
	protocol.RelayNode
	NetworkID  string `json:"network_id,omitempty"`
	State      string `json:"state"`
	Registered bool   `json:"registered"`
	Online     bool   `json:"online"`
	Priority   int    `json:"priority"`
	protocol.NodeLimits
	protocol.NodeStats
	LastSeen int64 `json:"last_seen"`
}
type nodeRecord struct {
	NodeView
	identity, inviteHash string
	inviteExpires        int64
}

const nodeCols = "id,region,relay_url,stun_url,coalesce(network_id,''),state,priority,max_connections,bytes_per_second,last_seen,connections,ingress,egress,dropped,coalesce(identity,''),coalesce(invite_hash,''),invite_expires"

func scanNode(row interface{ Scan(...any) error }) (nodeRecord, error) {
	var n nodeRecord
	e := row.Scan(&n.ID, &n.Region, &n.RelayURL, &n.STUNURL, &n.NetworkID, &n.State, &n.Priority, &n.MaxConnections, &n.BytesPerSecond, &n.LastSeen, &n.Connections, &n.Ingress, &n.Egress, &n.Dropped, &n.identity, &n.inviteHash, &n.inviteExpires)
	n.Registered = n.identity != ""
	n.Online = n.Registered && n.LastSeen >= now()-heartbeatTTL && n.State != "revoked"
	return n, e
}
func validRelayURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "wss" && u.Hostname() != "" && u.Path == "/relay/v1" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && len(raw) <= 512
}
func validSTUN(raw string) bool {
	if raw == "" {
		return true
	}
	u, e := stun.ParseURI(raw)
	return e == nil && u.Scheme == stun.SchemeTypeSTUN && u.Proto == stun.ProtoTypeUDP && len(raw) <= 512
}
func (s *Service) listNodes(w http.ResponseWriter, r *http.Request) error {
	if _, e := s.admin(r); e != nil {
		return e
	}
	rows, e := s.Store.DB.QueryContext(r.Context(), "SELECT "+nodeCols+" FROM relay_nodes ORDER BY id")
	if e != nil {
		return e
	}
	defer rows.Close()
	out := []NodeView{}
	for rows.Next() {
		n, e := scanNode(rows)
		if e != nil {
			return e
		}
		out = append(out, n.NodeView)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	return write(w, 200, out)
}
func (s *Service) createNode(w http.ResponseWriter, r *http.Request) error {
	u, e := s.admin(r)
	if e != nil {
		return e
	}
	var v struct {
		ID             string `json:"id"`
		Region         string `json:"region"`
		RelayURL       string `json:"relay_url"`
		STUNURL        string `json:"stun_url"`
		NetworkID      string `json:"network_id"`
		Priority       int    `json:"priority"`
		MaxConnections int    `json:"max_connections"`
		BytesPerSecond int64  `json:"bytes_per_second"`
	}
	if e = decode(w, r, &v); e != nil {
		return e
	}
	v.Region = strings.TrimSpace(v.Region)
	if !nodeID.MatchString(v.ID) || v.ID == s.Node || v.Region == "" || len(v.Region) > 64 || !validRelayURL(v.RelayURL) || !validSTUN(v.STUNURL) || v.RelayURL == s.RelayURL || v.Priority < 0 || v.Priority > 100 || v.MaxConnections < 2 || v.MaxConnections > 256 || v.BytesPerSecond < 65536 || v.BytesPerSecond > 1<<30 {
		return failure(400, "invalid relay metadata or limits")
	}
	token, e := random(32)
	if e != nil {
		return e
	}
	exp := now() + 3600
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		var count int
		if e := tx.QueryRow("SELECT count(*) FROM relay_nodes WHERE state<>'revoked'").Scan(&count); e != nil {
			return e
		}
		if count >= maxNodes {
			return failure(409, "relay node quota reached")
		}
		if e := tx.QueryRow("SELECT count(*) FROM relay_nodes WHERE id=? OR relay_url=?", v.ID, v.RelayURL).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return failure(409, "node ID or relay URL already exists")
		}
		var scope any
		if v.NetworkID != "" {
			if _, e := network(tx, v.NetworkID, u); e != nil {
				return e
			}
			scope = v.NetworkID
		}
		if _, e := tx.Exec("INSERT INTO relay_nodes(id,region,relay_url,stun_url,network_id,invite_hash,invite_expires,state,priority,max_connections,bytes_per_second) VALUES(?,?,?,?,?,?,?,'active',?,?,?)", v.ID, v.Region, v.RelayURL, v.STUNURL, scope, digest(token), exp, v.Priority, v.MaxConnections, v.BytesPerSecond); e != nil {
			return e
		}
		return audit(tx, u.ID, "relay.create", v.ID)
	})
	if e != nil {
		return e
	}
	return write(w, 201, map[string]any{"id": v.ID, "invite": token, "expires": exp})
}
func (s *Service) nodeState(w http.ResponseWriter, r *http.Request) error {
	u, e := s.admin(r)
	if e != nil {
		return e
	}
	var v struct {
		State string `json:"state"`
	}
	if e = decode(w, r, &v); e != nil {
		return e
	}
	if v.State != "active" && v.State != "draining" && v.State != "revoked" {
		return failure(400, "invalid relay state")
	}
	id := r.PathValue("id")
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		n, e := scanNode(tx.QueryRow("SELECT "+nodeCols+" FROM relay_nodes WHERE id=?", id))
		if e != nil {
			return e
		}
		if n.State == "revoked" {
			return failure(409, "revoked relay cannot be reactivated")
		}
		if _, e = tx.Exec("UPDATE relay_nodes SET state=? WHERE id=?", v.State, id); e != nil {
			return e
		}
		if v.State == "revoked" {
			if _, e = tx.Exec("DELETE FROM pair_relays WHERE node_id=?", id); e != nil {
				return e
			}
		}
		return audit(tx, u.ID, "relay."+v.State, id)
	})
	if e != nil {
		return e
	}
	return write(w, 200, map[string]bool{"ok": true})
}
func (s *Service) nodeLimits(w http.ResponseWriter, r *http.Request) error {
	u, e := s.admin(r)
	if e != nil {
		return e
	}
	var v protocol.NodeLimits
	if e = decode(w, r, &v); e != nil {
		return e
	}
	if v.MaxConnections < 2 || v.MaxConnections > 256 || v.BytesPerSecond < 65536 || v.BytesPerSecond > 1<<30 {
		return failure(400, "invalid relay limits")
	}
	id := r.PathValue("id")
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		n, e := scanNode(tx.QueryRow("SELECT "+nodeCols+" FROM relay_nodes WHERE id=?", id))
		if e != nil {
			return e
		}
		if n.State == "revoked" {
			return failure(409, "revoked node")
		}
		if _, e = tx.Exec("UPDATE relay_nodes SET max_connections=?,bytes_per_second=? WHERE id=?", v.MaxConnections, v.BytesPerSecond, id); e != nil {
			return e
		}
		return audit(tx, u.ID, "relay.limits", id)
	})
	if e != nil {
		return e
	}
	return write(w, 200, v)
}
func (s *Service) nodeRequest(w http.ResponseWriter, r *http.Request) error {
	var v protocol.NodeRequest
	if e := decode(w, r, &v); e != nil {
		return e
	}
	if !nodeID.MatchString(v.ID) || !(v.Action == "enroll" || v.Action == "heartbeat" || v.Action == "authorize") {
		return failure(400, "invalid node action")
	}
	var reply protocol.NodeReply
	e := withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		n, e := scanNode(tx.QueryRow("SELECT "+nodeCols+" FROM relay_nodes WHERE id=?", v.ID))
		if errors.Is(e, sql.ErrNoRows) {
			return failure(401, "unknown node")
		}
		if e != nil {
			return e
		}
		if n.State == "revoked" {
			return failure(403, "node revoked")
		}
		switch v.Action {
		case "enroll":
			if len(v.Invite) != 43 || n.identity != "" || n.inviteHash == "" || n.inviteExpires <= now() || digest(v.Invite) != n.inviteHash || !v.Verify(v.Identity) || v.Stats != nil || len(v.Lease) != 0 {
				return failure(403, "invalid or consumed node invitation")
			}
			if _, e = tx.Exec("UPDATE relay_nodes SET identity=?,invite_hash=NULL WHERE id=?", v.Identity, v.ID); e != nil {
				return e
			}
			if e = audit(tx, v.ID, "relay.enroll", v.ID); e != nil {
				return e
			}
		default:
			if n.identity == "" || v.Invite != "" || v.Identity != "" || !v.Verify(n.identity) {
				return failure(401, "invalid node proof")
			}
		}
		t := now()
		if _, e = tx.Exec("DELETE FROM node_nonces WHERE expires<=?", t); e != nil {
			return e
		}
		res, e := tx.Exec("INSERT OR IGNORE INTO node_nonces VALUES(?,?,?)", v.ID, v.Nonce, t+90)
		if e != nil {
			return e
		}
		count, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if count != 1 {
			return failure(409, "replayed node request")
		}
		reply = protocol.NodeReply{Node: n.RelayNode, State: n.State, Limits: n.NodeLimits}
		if v.Action == "heartbeat" {
			x := v.Stats
			if x == nil || len(v.Lease) != 0 || x.Connections < 0 || x.Connections > 256 || x.Ingress > 1<<62 || x.Egress > 1<<62 || x.Dropped > 1<<62 {
				return failure(400, "invalid node statistics")
			}
			_, e = tx.Exec("UPDATE relay_nodes SET last_seen=?,connections=?,ingress=?,egress=?,dropped=? WHERE id=?", t, x.Connections, x.Ingress, x.Egress, x.Dropped, v.ID)
			return e
		}
		if v.Action == "authorize" {
			if v.Stats != nil || len(v.Lease) > 4096 {
				return failure(400, "invalid lease query")
			}
			var l relay.Lease
			if e = json.Unmarshal(v.Lease, &l); e != nil || l.Node != v.ID || l.Valid(time.Now()) != nil {
				return failure(400, "invalid lease query")
			}
			if !n.Online {
				return nil
			}
			reply.Authorized, e = s.authorizeLeaseTx(tx, l)
			return e
		}
		return nil
	})
	if e != nil {
		return e
	}
	return write(w, 200, reply)
}
func (s *Service) eligible(tx *sql.Tx, network string) ([]NodeView, error) {
	rows, e := tx.Query("SELECT "+nodeCols+" FROM relay_nodes WHERE state='active' AND identity IS NOT NULL AND last_seen>=? AND (network_id IS NULL OR network_id=?) ORDER BY id", now()-heartbeatTTL, network)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []NodeView{}
	for rows.Next() {
		n, e := scanNode(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, n.NodeView)
	}
	return out, rows.Err()
}
func (s *Service) recordProbes(tx *sql.Tx, d Device, probes []protocol.NodeProbe) error {
	if len(probes) > maxNodes {
		return failure(400, "too many probes")
	}
	seen := map[string]bool{}
	for _, p := range probes {
		if !nodeID.MatchString(p.ID) || seen[p.ID] || p.RTTMillis < 0 || p.RTTMillis > 10000 {
			return failure(400, "invalid node probe")
		}
		seen[p.ID] = true
		var count int
		if e := tx.QueryRow("SELECT count(*) FROM relay_nodes WHERE id=? AND state<>'revoked' AND (network_id IS NULL OR network_id=?)", p.ID, d.NetworkID).Scan(&count); e != nil {
			return e
		}
		if count == 0 {
			continue
		}
		fail := 0
		if !p.Reachable {
			fail = 1
		}
		if _, e := tx.Exec("INSERT INTO node_probes VALUES(?,?,?,?,?) ON CONFLICT(device_id,node_id) DO UPDATE SET rtt=excluded.rtt, failures=CASE WHEN excluded.failures=0 THEN 0 WHEN node_probes.observed<excluded.observed-20 THEN 1 ELSE min(3,node_probes.failures+1) END, observed=excluded.observed", d.ID, p.ID, p.RTTMillis, fail, now()); e != nil {
			return e
		}
	}
	return nil
}

type probe struct {
	rtt, fail int
	observed  int64
	known     bool
}

func getProbe(tx *sql.Tx, device, node string) (probe, error) {
	var p probe
	e := tx.QueryRow("SELECT rtt,failures,observed FROM node_probes WHERE device_id=? AND node_id=?", device, node).Scan(&p.rtt, &p.fail, &p.observed)
	if errors.Is(e, sql.ErrNoRows) {
		return p, nil
	}
	if e != nil {
		return p, e
	}
	p.known = p.observed >= now()-probeTTL
	return p, nil
}

type scored struct {
	node   NodeView
	score  int
	known  bool
	failed bool
}

// A shared durable assignment prevents the two devices from selecting different relays.
func (s *Service) chooseNode(tx *sql.Tx, nid, a, b string, nodes []NodeView) (protocol.RelayNode, error) {
	var current string
	var changed int64
	e := tx.QueryRow("SELECT node_id,changed FROM pair_relays WHERE network_id=? AND a=? AND b=?", nid, a, b).Scan(&current, &changed)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return protocol.RelayNode{}, e
	}
	scores := []scored{}
	for _, n := range nodes {
		x, e := getProbe(tx, a, n.ID)
		if e != nil {
			return protocol.RelayNode{}, e
		}
		y, e := getProbe(tx, b, n.ID)
		if e != nil {
			return protocol.RelayNode{}, e
		}
		failed := (x.known && x.fail >= 2) || (y.known && y.fail >= 2)
		both := x.known && x.fail == 0 && y.known && y.fail == 0
		rtt := 200
		if x.known && x.fail == 0 {
			rtt = x.rtt + 100
		}
		if y.known && y.fail == 0 {
			if x.known && x.fail == 0 {
				rtt = x.rtt + y.rtt
			} else {
				rtt = 100 + y.rtt
			}
		}
		// Account for reserved pairs, not only currently connected sockets.
		var reserved int
		if e = tx.QueryRow("SELECT count(*) FROM pair_relays WHERE node_id=?", n.ID).Scan(&reserved); e != nil {
			return protocol.RelayNode{}, e
		}
		load := n.Connections
		if reserved*2 > load {
			load = reserved * 2
		}
		if n.ID != current && load+2 > n.MaxConnections {
			continue
		}
		score := rtt + n.Priority*10 + 100*load/n.MaxConnections
		scores = append(scores, scored{n, score, both, failed})
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].score == scores[j].score {
			return scores[i].node.ID < scores[j].node.ID
		}
		return scores[i].score < scores[j].score
	})
	var best protocol.RelayNode
	var candidate *scored
	var old *scored
	for i := range scores {
		v := &scores[i]
		if v.node.ID == current {
			old = v
		}
		if !v.failed && candidate == nil {
			candidate = v
		}
	}
	if old != nil && !old.failed {
		best = old.node.RelayNode
		if candidate != nil && candidate.node.ID != old.node.ID && candidate.known && old.known && now()-changed >= 30 && old.score-candidate.score >= 60 {
			best = candidate.node.RelayNode
		}
	} else if candidate != nil {
		best = candidate.node.RelayNode
	}
	if best.ID == "" && s.RelayURL != "" {
		best = protocol.RelayNode{ID: s.Node, Region: "static", RelayURL: s.RelayURL, STUNURL: s.STUNURL}
	}
	if best.ID == "" {
		_, e = tx.Exec("DELETE FROM pair_relays WHERE network_id=? AND a=? AND b=?", nid, a, b)
		return best, e
	}
	if current != best.ID {
		_, e = tx.Exec("INSERT INTO pair_relays VALUES(?,?,?,?,?) ON CONFLICT(network_id,a,b) DO UPDATE SET node_id=excluded.node_id,changed=excluded.changed", nid, a, b, best.ID, now())
		if e != nil {
			return best, e
		}
	}
	return best, nil
}
func (s *Service) authorizeLeaseTx(tx *sql.Tx, l relay.Lease) (bool, error) {
	var a, b string
	var rev int64
	var policy string
	if e := tx.QueryRow("SELECT id FROM devices WHERE network_id=? AND identity=? AND status='approved'", l.Network, l.A).Scan(&a); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return false, nil
		}
		return false, e
	}
	if e := tx.QueryRow("SELECT id FROM devices WHERE network_id=? AND identity=? AND status='approved'", l.Network, l.B).Scan(&b); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return false, nil
		}
		return false, e
	}
	if e := tx.QueryRow("SELECT revision,policy FROM networks WHERE id=?", l.Network).Scan(&rev, &policy); e != nil {
		return false, e
	}
	if a > b {
		a, b = b, a
	}
	var selected string
	if e := tx.QueryRow("SELECT node_id FROM pair_relays WHERE network_id=? AND a=? AND b=?", l.Network, a, b).Scan(&selected); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return false, nil
		}
		return false, e
	}
	if selected != l.Node {
		return false, nil
	}
	if l.Node != s.Node {
		n, e := scanNode(tx.QueryRow("SELECT "+nodeCols+" FROM relay_nodes WHERE id=?", l.Node))
		if e != nil {
			return false, e
		}
		if !n.Online || n.State == "revoked" || (n.NetworkID != "" && n.NetworkID != l.Network) {
			return false, nil
		}
	} else if s.RelayURL == "" {
		return false, nil
	}
	epoch := (l.Expires-30)/120 - 1
	if (epoch+1)*120+30 != l.Expires || l.Flow != digest(l.Network+":"+a+":"+b+":"+intString(rev)+":"+intString(epoch)) {
		return false, nil
	}
	allow := policy == "allow_members"
	var override bool
	e := tx.QueryRow("SELECT allow FROM pair_rules WHERE network_id=? AND a=? AND b=?", l.Network, a, b).Scan(&override)
	if e == nil {
		return override, nil
	}
	if errors.Is(e, sql.ErrNoRows) {
		return allow, nil
	}
	return false, e
}
func (s *Service) authorizeCurrent(l relay.Lease) bool {
	if l.Valid(time.Now()) != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var ok bool
	e := withTx(ctx, s.Store, func(tx *sql.Tx) error { var e error; ok, e = s.authorizeLeaseTx(tx, l); return e })
	return e == nil && ok
}
