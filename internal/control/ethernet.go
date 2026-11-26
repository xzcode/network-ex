package control

import (
	"database/sql"
	"net/http"
)

const schemaV6 = `
ALTER TABLE devices ADD COLUMN ethernet_enabled INTEGER NOT NULL DEFAULT 0 CHECK(ethernet_enabled IN (0,1));
CREATE TABLE ethernet_networks(network_id TEXT PRIMARY KEY REFERENCES networks(id));
PRAGMA user_version=6;
`

type ethernetPolicy struct {
	Enabled bool `json:"enabled"`
}

func ethernetFor(tx *sql.Tx, nid string) (bool, error) {
	var n int
	e := tx.QueryRow("SELECT count(*) FROM ethernet_networks WHERE network_id=?", nid).Scan(&n)
	return n != 0, e
}
func (s *Service) getEthernet(w http.ResponseWriter, r *http.Request) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	nid := r.PathValue("id")
	var enabled bool
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		if _, e := network(tx, nid, u); e != nil {
			return e
		}
		enabled, e = ethernetFor(tx, nid)
		return e
	})
	if e != nil {
		return e
	}
	return write(w, 200, ethernetPolicy{enabled})
}
func (s *Service) setEthernet(w http.ResponseWriter, r *http.Request) error {
	u, e := s.admin(r)
	if e != nil {
		return e
	}
	var p ethernetPolicy
	if e = decode(w, r, &p); e != nil {
		return e
	}
	nid := r.PathValue("id")
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		if _, e := network(tx, nid, u); e != nil {
			return e
		}
		old, e := ethernetFor(tx, nid)
		if e != nil {
			return e
		}
		if old == p.Enabled {
			return nil
		}
		if p.Enabled {
			var n int
			if e = tx.QueryRow("SELECT (SELECT count(*) FROM subnet_routes WHERE network_id=?)+(SELECT count(*) FROM exit_grants WHERE network_id=?)", nid, nid).Scan(&n); e != nil {
				return e
			}
			if n != 0 {
				return failure(409, "remove subnet routes and exit grants before enabling Ethernet mode")
			}
			if _, e = tx.Exec("INSERT INTO ethernet_networks VALUES(?)", nid); e != nil {
				return e
			}
		} else {
			if _, e = tx.Exec("DELETE FROM ethernet_networks WHERE network_id=?", nid); e != nil {
				return e
			}
		}
		if _, e = tx.Exec("UPDATE devices SET ethernet_enabled=0 WHERE network_id=?", nid); e != nil {
			return e
		}
		if _, e = tx.Exec("UPDATE networks SET revision=revision+1 WHERE id=?", nid); e != nil {
			return e
		}
		return audit(tx, u.ID, "ethernet.update", nid)
	})
	if e != nil {
		return e
	}
	return write(w, 200, p)
}
