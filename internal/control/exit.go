package control

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/xzcode/network-ex/pkg/protocol"
)

const schemaV4 = `
CREATE TABLE exit_grants(network_id TEXT NOT NULL REFERENCES networks(id), client_id TEXT NOT NULL REFERENCES devices(id), gateway_id TEXT NOT NULL REFERENCES devices(id), targets TEXT NOT NULL, PRIMARY KEY(network_id,client_id), CHECK(client_id<>gateway_id));
PRAGMA user_version=4;
`

func exitFor(tx *sql.Tx, nid string) (map[string]protocol.ExitGrant, error) {
	rows, e := tx.Query("SELECT client_id,gateway_id,targets FROM exit_grants WHERE network_id=? ORDER BY client_id", nid)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]protocol.ExitGrant{}
	for rows.Next() {
		var g protocol.ExitGrant
		var b string
		if e = rows.Scan(&g.Client, &g.Gateway, &b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(b), &g.Targets); e != nil {
			return nil, e
		}
		if _, e = protocol.ValidateExitTargets(g.Targets); e != nil {
			return nil, e
		}
		out[g.Client] = g
	}
	return out, rows.Err()
}
func (s *Service) listExit(w http.ResponseWriter, r *http.Request) error {
	u, e := s.admin(r)
	if e != nil {
		return e
	}
	nid := r.PathValue("id")
	out := []protocol.ExitGrant{}
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		if _, e := network(tx, nid, u); e != nil {
			return e
		}
		gs, e := exitFor(tx, nid)
		if e != nil {
			return e
		}
		for _, g := range gs {
			out = append(out, g)
		}
		return nil
	})
	if e != nil {
		return e
	}
	return write(w, 200, out)
}
func (s *Service) setExit(w http.ResponseWriter, r *http.Request) error {
	u, e := s.admin(r)
	if e != nil {
		return e
	}
	var g protocol.ExitGrant
	if e = decode(w, r, &g); e != nil {
		return e
	}
	ps, e := protocol.ValidateExitTargets(g.Targets)
	if e != nil {
		return failure(400, e.Error())
	}
	if g.Client == "" || (len(ps) > 0 && (g.Gateway == "" || g.Client == g.Gateway)) {
		return failure(400, "distinct approved client and gateway required")
	}
	g.Targets = []string{}
	for _, p := range ps {
		g.Targets = append(g.Targets, p.Addr().String())
	}
	nid := r.PathValue("id")
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		n, e := network(tx, nid, u)
		if e != nil {
			return e
		}
		var count int
		if e = tx.QueryRow("SELECT count(*) FROM devices WHERE network_id=? AND id=?", nid, g.Client).Scan(&count); e != nil {
			return e
		}
		if count != 1 {
			return failure(404, "client not found")
		}
		if len(ps) > 0 {
			enabled, e := ethernetFor(tx, nid)
			if e != nil {
				return e
			}
			if enabled {
				return failure(409, "exit grants are not supported in Ethernet mode")
			}
		}
		if len(ps) == 0 {
			if _, e = tx.Exec("DELETE FROM exit_grants WHERE network_id=? AND client_id=?", nid, g.Client); e != nil {
				return e
			}
		} else {
			if e = tx.QueryRow("SELECT count(*) FROM devices WHERE network_id=? AND status='approved' AND id IN (?,?)", nid, g.Client, g.Gateway).Scan(&count); e != nil {
				return e
			}
			if count != 2 {
				return failure(400, "both devices must be approved in this network")
			}
			a, b := g.Client, g.Gateway
			if a > b {
				a, b = b, a
			}
			allow := n.Policy == "allow_members"
			var explicit bool
			e = tx.QueryRow("SELECT allow FROM pair_rules WHERE network_id=? AND a=? AND b=?", nid, a, b).Scan(&explicit)
			if e == nil {
				allow = explicit
			} else if e != sql.ErrNoRows {
				return e
			}
			if !allow {
				return failure(403, "device pair must be allowed first")
			}
			// No chaining/cycles: a client cannot be an exit gateway in this network.
			if e = tx.QueryRow("SELECT count(*) FROM exit_grants WHERE network_id=? AND (gateway_id=? OR client_id=?)", nid, g.Client, g.Gateway).Scan(&count); e != nil {
				return e
			}
			if count != 0 {
				return failure(409, "exit chaining is not supported")
			}
			raw, e := json.Marshal(g.Targets)
			if e != nil {
				return e
			}
			if _, e = tx.Exec("INSERT INTO exit_grants VALUES(?,?,?,?) ON CONFLICT(network_id,client_id) DO UPDATE SET gateway_id=excluded.gateway_id,targets=excluded.targets", nid, g.Client, g.Gateway, string(raw)); e != nil {
				return e
			}
		}
		if _, e = tx.Exec("UPDATE networks SET revision=revision+1 WHERE id=?", nid); e != nil {
			return e
		}
		return audit(tx, u.ID, "exit.update", g.Client)
	})
	if e != nil {
		return e
	}
	return write(w, 200, g)
}
