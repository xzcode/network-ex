package control

import (
	"database/sql"
	"encoding/json"
	"github.com/xzcode/network-ex/pkg/protocol"
	"net/http"
)

const schemaV5 = `
ALTER TABLE devices ADD COLUMN discovery_enabled INTEGER NOT NULL DEFAULT 0 CHECK(discovery_enabled IN (0,1));
CREATE TABLE discovery_policies(network_id TEXT PRIMARY KEY REFERENCES networks(id), rules TEXT NOT NULL);
PRAGMA user_version=5;
`

func discoveryFor(tx *sql.Tx, nid string) (protocol.DiscoveryPolicy, error) {
	p := protocol.DiscoveryPolicy{Rules: []protocol.DiscoveryRule{}}
	var raw string
	e := tx.QueryRow("SELECT rules FROM discovery_policies WHERE network_id=?", nid).Scan(&raw)
	if e == sql.ErrNoRows {
		return p, nil
	}
	if e != nil {
		return p, e
	}
	e = json.Unmarshal([]byte(raw), &p)
	return p, e
}
func (s *Service) getDiscovery(w http.ResponseWriter, r *http.Request) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	nid := r.PathValue("id")
	var p protocol.DiscoveryPolicy
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		n, e := network(tx, nid, u)
		if e != nil {
			return e
		}
		p, e = discoveryFor(tx, nid)
		if e != nil {
			return e
		}
		return p.Validate(n.CIDR)
	})
	if e != nil {
		return e
	}
	return write(w, 200, p)
}
func (s *Service) setDiscovery(w http.ResponseWriter, r *http.Request) error {
	u, e := s.admin(r)
	if e != nil {
		return e
	}
	var p protocol.DiscoveryPolicy
	if e = decode(w, r, &p); e != nil {
		return e
	}
	nid := r.PathValue("id")
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		n, e := network(tx, nid, u)
		if e != nil {
			return e
		}
		if e = p.Validate(n.CIDR); e != nil {
			return failure(400, e.Error())
		}
		p.Normalize()
		if len(p.Rules) == 0 {
			if _, e = tx.Exec("DELETE FROM discovery_policies WHERE network_id=?", nid); e != nil {
				return e
			}
		} else {
			b, e := json.Marshal(p)
			if e != nil {
				return e
			}
			if _, e = tx.Exec("INSERT INTO discovery_policies VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET rules=excluded.rules", nid, string(b)); e != nil {
				return e
			}
		}
		if _, e = tx.Exec("UPDATE networks SET revision=revision+1 WHERE id=?", nid); e != nil {
			return e
		}
		return audit(tx, u.ID, "discovery.update", nid)
	})
	if e != nil {
		return e
	}
	return write(w, 200, p)
}
