package control

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"sort"

	"github.com/xzcode/network-ex/pkg/protocol"
)

const schemaV3 = `
CREATE TABLE subnet_routes(network_id TEXT NOT NULL REFERENCES networks(id), device_id TEXT NOT NULL REFERENCES devices(id), cidr TEXT NOT NULL UNIQUE, PRIMARY KEY(network_id,device_id,cidr));
CREATE TABLE traffic_rules(network_id TEXT NOT NULL REFERENCES networks(id), a TEXT NOT NULL REFERENCES devices(id), b TEXT NOT NULL REFERENCES devices(id), services TEXT NOT NULL, PRIMARY KEY(network_id,a,b), CHECK(a<b));
CREATE TABLE dns_aliases(network_id TEXT NOT NULL REFERENCES networks(id), device_id TEXT NOT NULL REFERENCES devices(id), label TEXT NOT NULL, PRIMARY KEY(network_id,device_id), UNIQUE(network_id,label));
PRAGMA user_version=3;
`

type advancedDevice struct {
	DeviceID string   `json:"device_id"`
	Subnets  []string `json:"subnets"`
	DNSLabel string   `json:"dns_label"`
}
type trafficRule struct {
	A      string                  `json:"a"`
	B      string                  `json:"b"`
	Policy *protocol.TrafficPolicy `json:"policy"`
}
type advancedView struct {
	Devices []advancedDevice `json:"devices"`
	Rules   []trafficRule    `json:"rules"`
}

func advancedFor(tx *sql.Tx, nid string) (map[string]advancedDevice, map[[2]string]*protocol.TrafficPolicy, error) {
	ds := map[string]advancedDevice{}
	rs := map[[2]string]*protocol.TrafficPolicy{}
	rows, e := tx.Query("SELECT device_id,cidr FROM subnet_routes WHERE network_id=? ORDER BY cidr", nid)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var id, c string
		if e = rows.Scan(&id, &c); e != nil {
			rows.Close()
			return nil, nil, e
		}
		v := ds[id]
		v.DeviceID = id
		v.Subnets = append(v.Subnets, c)
		ds[id] = v
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	rows, e = tx.Query("SELECT device_id,label FROM dns_aliases WHERE network_id=?", nid)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var id, l string
		if e = rows.Scan(&id, &l); e != nil {
			rows.Close()
			return nil, nil, e
		}
		v := ds[id]
		v.DeviceID = id
		v.DNSLabel = l
		ds[id] = v
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	rows, e = tx.Query("SELECT a,b,services FROM traffic_rules WHERE network_id=?", nid)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var a, b, s string
		if e = rows.Scan(&a, &b, &s); e != nil {
			rows.Close()
			return nil, nil, e
		}
		var p protocol.TrafficPolicy
		if e = json.Unmarshal([]byte(s), &p); e != nil || p.Validate() != nil {
			rows.Close()
			return nil, nil, errors.New("invalid stored traffic policy")
		}
		rs[[2]string{a, b}] = &p
	}
	e = rows.Err()
	rows.Close()
	return ds, rs, e
}
func (s *Service) advanced(w http.ResponseWriter, r *http.Request) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	nid := r.PathValue("id")
	out := advancedView{Devices: []advancedDevice{}, Rules: []trafficRule{}}
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		if _, e := network(tx, nid, u); e != nil {
			return e
		}
		ds, rs, e := advancedFor(tx, nid)
		if e != nil {
			return e
		}
		for _, v := range ds {
			if v.Subnets == nil {
				v.Subnets = []string{}
			}
			out.Devices = append(out.Devices, v)
		}
		for k, p := range rs {
			out.Rules = append(out.Rules, trafficRule{k[0], k[1], p})
		}
		sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].DeviceID < out.Devices[j].DeviceID })
		sort.Slice(out.Rules, func(i, j int) bool {
			a, b := out.Rules[i], out.Rules[j]
			if a.A == b.A {
				return a.B < b.B
			}
			return a.A < b.A
		})
		return nil
	})
	if e != nil {
		return e
	}
	return write(w, 200, out)
}

// Global non-overlap is deliberate: current overlay addressing is not VRF-based.
func subnetConflicts(tx *sql.Tx, proposed netip.Prefix, exceptDevice string) error {
	for _, q := range []struct {
		query string
		args  []any
	}{{"SELECT cidr FROM networks", nil}, {"SELECT cidr FROM subnet_routes WHERE device_id<>?", []any{exceptDevice}}} {
		rows, e := tx.Query(q.query, q.args...)
		if e != nil {
			return e
		}
		for rows.Next() {
			var raw string
			if e = rows.Scan(&raw); e != nil {
				rows.Close()
				return e
			}
			p, e := netip.ParsePrefix(raw)
			if e != nil {
				rows.Close()
				return e
			}
			if proposed.Overlaps(p) {
				rows.Close()
				return failure(409, "subnet overlaps an existing overlay or approved subnet")
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) setAdvancedDevice(w http.ResponseWriter, r *http.Request) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	var v struct {
		Subnets  []string `json:"subnets"`
		DNSLabel string   `json:"dns_label"`
	}
	if e = decode(w, r, &v); e != nil {
		return e
	}
	ps, e := protocol.ValidateSubnets(v.Subnets)
	if e != nil {
		return failure(400, e.Error())
	}
	if v.DNSLabel != "" && !protocol.ValidDNSLabel(v.DNSLabel) {
		return failure(400, "invalid DNS label")
	}
	nid, id := r.PathValue("id"), r.PathValue("device")
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		if _, e := network(tx, nid, u); e != nil {
			return e
		}
		var n int
		if e := tx.QueryRow("SELECT count(*) FROM devices WHERE network_id=? AND id=? AND status='approved'", nid, id).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			return failure(404, "approved device not found")
		}
		// Only administrators can authorize forwarding physical LANs.
		if len(ps) > 0 && u.Role != "admin" {
			return failure(403, "administrator required to approve subnets")
		}
		if u.Role != "admin" {
			if e := tx.QueryRow("SELECT count(*) FROM subnet_routes WHERE device_id=?", id).Scan(&n); e != nil {
				return e
			}
			if n > 0 {
				return failure(403, "administrator required to change subnet configuration")
			}
		}
		for _, p := range ps {
			if e := subnetConflicts(tx, p, id); e != nil {
				return e
			}
		}
		if _, e := tx.Exec("DELETE FROM subnet_routes WHERE network_id=? AND device_id=?", nid, id); e != nil {
			return e
		}
		for _, p := range ps {
			if _, e := tx.Exec("INSERT INTO subnet_routes VALUES(?,?,?)", nid, id, p.String()); e != nil {
				return e
			}
		}
		if _, e := tx.Exec("DELETE FROM dns_aliases WHERE network_id=? AND device_id=?", nid, id); e != nil {
			return e
		}
		if v.DNSLabel != "" {
			if e := tx.QueryRow("SELECT count(*) FROM dns_aliases WHERE network_id=? AND label=?", nid, v.DNSLabel).Scan(&n); e != nil {
				return e
			}
			if n != 0 {
				return failure(409, "DNS label already used")
			}
			if _, e := tx.Exec("INSERT INTO dns_aliases VALUES(?,?,?)", nid, id, v.DNSLabel); e != nil {
				return e
			}
		}
		if _, e := tx.Exec("UPDATE networks SET revision=revision+1 WHERE id=?", nid); e != nil {
			return e
		}
		return audit(tx, u.ID, "device.advanced", id)
	})
	if e != nil {
		return e
	}
	sort.Strings(v.Subnets)
	return write(w, 200, advancedDevice{id, v.Subnets, v.DNSLabel})
}
func (s *Service) setTraffic(w http.ResponseWriter, r *http.Request) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	var v trafficRule
	if e = decode(w, r, &v); e != nil {
		return e
	}
	if v.A == v.B || v.A == "" || v.B == "" || v.Policy.Validate() != nil {
		return failure(400, "invalid device pair or service policy")
	}
	if v.A > v.B {
		v.A, v.B = v.B, v.A
	}
	v.Policy.Normalize()
	nid := r.PathValue("id")
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		if _, e := network(tx, nid, u); e != nil {
			return e
		}
		var n int
		if e := tx.QueryRow("SELECT count(*) FROM devices WHERE network_id=? AND status='approved' AND id IN (?,?)", nid, v.A, v.B).Scan(&n); e != nil {
			return e
		}
		if n != 2 {
			return failure(400, "both devices must be approved in this network")
		}
		if v.Policy == nil {
			if _, e := tx.Exec("DELETE FROM traffic_rules WHERE network_id=? AND a=? AND b=?", nid, v.A, v.B); e != nil {
				return e
			}
		} else {
			b, e := json.Marshal(v.Policy)
			if e != nil {
				return e
			}
			if _, e = tx.Exec("INSERT INTO traffic_rules VALUES(?,?,?,?) ON CONFLICT(network_id,a,b) DO UPDATE SET services=excluded.services", nid, v.A, v.B, string(b)); e != nil {
				return e
			}
		}
		if _, e := tx.Exec("UPDATE networks SET revision=revision+1 WHERE id=?", nid); e != nil {
			return e
		}
		return audit(tx, u.ID, "traffic.update", nid)
	})
	if e != nil {
		return e
	}
	return write(w, 200, v)
}
