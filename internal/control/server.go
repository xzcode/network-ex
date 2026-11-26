package control

import (
	"crypto/ed25519"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xzcode/network-ex/internal/dataplane/relay"
)

//go:embed web/*
var webFiles embed.FS

type apiFailure struct {
	code    int
	message string
}

func (e apiFailure) Error() string       { return e.message }
func failure(code int, msg string) error { return apiFailure{code, msg} }

type Service struct {
	Store                   *Store
	Issuer                  ed25519.PrivateKey
	Node, RelayURL, STUNURL string
	loginSlots              chan struct{}
	mu                      sync.Mutex
	loginWindow             time.Time
	loginCount              int
}

func NewService(store *Store, issuer ed25519.PrivateKey, node, relayURL, stunURL string) (*Service, error) {
	if store == nil || len(issuer) != ed25519.PrivateKeySize || node == "" || len(node) > 128 || (relayURL != "" && !validRelayURL(relayURL)) || !validSTUN(stunURL) {
		return nil, errors.New("invalid management node or relay/STUN URL")
	}
	return &Service{Store: store, Issuer: issuer, Node: node, RelayURL: relayURL, STUNURL: stunURL, loginSlots: make(chan struct{}, 2)}, nil
}

type handler func(http.ResponseWriter, *http.Request) error

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, h handler) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if e := h(w, r); e != nil {
				var f apiFailure
				if errors.As(e, &f) {
					write(w, f.code, map[string]string{"error": f.message})
				} else if errors.Is(e, sql.ErrNoRows) {
					write(w, 404, map[string]string{"error": "not found"})
				} else {
					write(w, 500, map[string]string{"error": "internal error"})
				}
			}
		})
	}
	route("GET /healthz", func(w http.ResponseWriter, r *http.Request) error {
		if e := s.Store.DB.PingContext(r.Context()); e != nil {
			return e
		}
		return write(w, 200, map[string]string{"status": "ok"})
	})
	route("POST /api/v1/auth/login", s.login)
	route("POST /api/v1/auth/logout", s.logout)
	route("GET /api/v1/me", func(w http.ResponseWriter, r *http.Request) error {
		u, e := s.user(r)
		if e != nil {
			return e
		}
		return write(w, 200, u)
	})
	route("GET /api/v1/users", s.users)
	route("POST /api/v1/users", s.createUser)
	route("GET /api/v1/networks", s.networks)
	route("POST /api/v1/networks", s.createNetwork)
	route("POST /api/v1/networks/{id}/invites", s.invite)
	route("GET /api/v1/networks/{id}/devices", s.devices)
	route("POST /api/v1/networks/{id}/devices/{device}/approve", s.approve)
	route("POST /api/v1/networks/{id}/devices/{device}/revoke", s.revoke)
	route("PUT /api/v1/networks/{id}/policy", s.policy)
	route("GET /api/v1/networks/{id}/rules", s.rules)
	route("PUT /api/v1/networks/{id}/rules", s.setRule)
	route("GET /api/v1/audit", s.auditList)
	route("POST /api/v1/devices/enroll", s.enroll)
	route("POST /api/v1/devices/snapshot", s.snapshot)
	route("GET /api/v1/networks/{id}/advanced", s.advanced)
	route("PUT /api/v1/networks/{id}/devices/{device}/advanced", s.setAdvancedDevice)
	route("PUT /api/v1/networks/{id}/traffic", s.setTraffic)
	route("GET /api/v1/networks/{id}/exit", s.listExit)
	route("PUT /api/v1/networks/{id}/exit", s.setExit)

	route("GET /api/v1/relay/nodes", s.listNodes)
	route("POST /api/v1/relay/nodes", s.createNode)
	route("PUT /api/v1/relay/nodes/{id}/state", s.nodeState)
	route("PUT /api/v1/relay/nodes/{id}/limits", s.nodeLimits)
	route("POST /api/v1/relay/node", s.nodeRequest)

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		contentType := map[string]string{"/index.html": "text/html; charset=utf-8", "/app.js": "application/javascript; charset=utf-8", "/app.css": "text/css; charset=utf-8"}[path]
		if contentType == "" {
			http.NotFound(w, r)
			return
		}
		b, e := webFiles.ReadFile("web" + path)
		if e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Write(b)
	})
	return mux
}
func write(w http.ResponseWriter, code int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	return json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		return failure(415, "application/json required")
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return failure(400, "invalid JSON")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return failure(400, "invalid JSON trailing content")
	}
	return nil
}
func bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return ""
	}
	t := strings.TrimPrefix(v, "Bearer ")
	if len(t) != 43 {
		return ""
	}
	return t
}
func (s *Service) user(r *http.Request) (User, error) {
	var u User
	t := bearer(r)
	if t == "" {
		return u, failure(401, "authentication required")
	}
	e := s.Store.DB.QueryRowContext(r.Context(), "SELECT u.id,u.login,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.hash=? AND s.expires>?", digest(t), now()).Scan(&u.ID, &u.Login, &u.Role)
	if errors.Is(e, sql.ErrNoRows) {
		return u, failure(401, "session expired or invalid")
	}
	return u, e
}
func (s *Service) admin(r *http.Request) (User, error) {
	u, e := s.user(r)
	if e == nil && u.Role != "admin" {
		e = failure(403, "administrator required")
	}
	return u, e
}
func (s *Service) permitLogin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.loginWindow) > time.Minute {
		s.loginWindow = time.Now()
		s.loginCount = 0
	}
	s.loginCount++
	return s.loginCount <= 60
}
func (s *Service) login(w http.ResponseWriter, r *http.Request) error {
	var v struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if e := decode(w, r, &v); e != nil {
		return e
	}
	if !s.permitLogin() {
		return failure(429, "login rate limit")
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		return failure(429, "login busy")
	}
	var u User
	var h string
	e := s.Store.DB.QueryRowContext(r.Context(), "SELECT id,login,role,password_hash FROM users WHERE login=?", loginName(v.Login)).Scan(&u.ID, &u.Login, &u.Role, &h)
	if errors.Is(e, sql.ErrNoRows) {
		h = "AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		checkPassword(v.Password, h)
		return failure(401, "invalid credentials")
	}
	if e != nil {
		return e
	}
	if !checkPassword(v.Password, h) {
		return failure(401, "invalid credentials")
	}
	token, e := random(32)
	if e != nil {
		return e
	}
	expires := now() + 3600
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		if _, e := tx.Exec("DELETE FROM sessions WHERE expires<=?", now()); e != nil {
			return e
		}
		_, e := tx.Exec("INSERT INTO sessions VALUES(?,?,?)", digest(token), u.ID, expires)
		return e
	})
	if e != nil {
		return e
	}
	return write(w, 200, map[string]any{"token": token, "expires": expires, "user": u})
}
func (s *Service) logout(w http.ResponseWriter, r *http.Request) error {
	if _, e := s.user(r); e != nil {
		return e
	}
	_, e := s.Store.DB.ExecContext(r.Context(), "DELETE FROM sessions WHERE hash=?", digest(bearer(r)))
	if e != nil {
		return e
	}
	return write(w, 200, map[string]bool{"ok": true})
}
func (s *Service) users(w http.ResponseWriter, r *http.Request) error {
	if _, e := s.admin(r); e != nil {
		return e
	}
	rows, e := s.Store.DB.QueryContext(r.Context(), "SELECT id,login,role FROM users ORDER BY login")
	if e != nil {
		return e
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var v User
		if e = rows.Scan(&v.ID, &v.Login, &v.Role); e != nil {
			return e
		}
		out = append(out, v)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	return write(w, 200, out)
}
func (s *Service) createUser(w http.ResponseWriter, r *http.Request) error {
	u, e := s.admin(r)
	if e != nil {
		return e
	}
	var v struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if e = decode(w, r, &v); e != nil {
		return e
	}
	v.Login = loginName(v.Login)
	if !validLogin(v.Login) {
		return failure(400, "invalid login")
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		return failure(429, "busy")
	}
	h, e := passwordHash(v.Password)
	if e != nil {
		return failure(400, e.Error())
	}
	id, e := random(18)
	if e != nil {
		return e
	}
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		var n int
		if e := tx.QueryRow("SELECT count(*) FROM users WHERE login=?", v.Login).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return failure(409, "login exists")
		}
		if _, e := tx.Exec("INSERT INTO users VALUES(?,?,?,?,?)", id, v.Login, h, "member", now()); e != nil {
			return e
		}
		return audit(tx, u.ID, "user.create", id)
	})
	if e != nil {
		return e
	}
	return write(w, 201, User{ID: id, Login: v.Login, Role: "member"})
}
func network(tx *sql.Tx, id string, u User) (Network, error) {
	var n Network
	e := tx.QueryRow("SELECT id,name,cidr,revision,policy,owner_id FROM networks WHERE id=?", id).Scan(&n.ID, &n.Name, &n.CIDR, &n.Revision, &n.Policy, &n.OwnerID)
	if e != nil {
		return n, e
	}
	if u.Role != "admin" && u.ID != n.OwnerID {
		return n, failure(404, "network not found")
	}
	return n, nil
}
func (s *Service) networks(w http.ResponseWriter, r *http.Request) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	rows, e := s.Store.DB.QueryContext(r.Context(), "SELECT id,name,cidr,revision,policy,owner_id FROM networks WHERE owner_id=? OR ?='admin' ORDER BY name", u.ID, u.Role)
	if e != nil {
		return e
	}
	defer rows.Close()
	out := []Network{}
	for rows.Next() {
		var n Network
		if e = rows.Scan(&n.ID, &n.Name, &n.CIDR, &n.Revision, &n.Policy, &n.OwnerID); e != nil {
			return e
		}
		out = append(out, n)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	return write(w, 200, out)
}
func (s *Service) createNetwork(w http.ResponseWriter, r *http.Request) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	var v struct {
		Name   string `json:"name"`
		CIDR   string `json:"cidr"`
		Policy string `json:"policy"`
	}
	if e = decode(w, r, &v); e != nil {
		return e
	}
	v.Name = strings.TrimSpace(v.Name)
	p, e := prefix(v.CIDR)
	if e != nil || len(v.Name) == 0 || len(v.Name) > 80 {
		return failure(400, "invalid name or private IPv4 CIDR (/24–/28)")
	}
	if v.Policy != "allow_members" && v.Policy != "deny_members" {
		return failure(400, "explicit policy required")
	}
	id, e := random(18)
	if e != nil {
		return e
	}
	n := Network{id, v.Name, p.String(), 1, v.Policy, u.ID}
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		if e := subnetConflicts(tx, p, ""); e != nil {
			return e
		}
		if _, e = tx.Exec("INSERT INTO networks(id,owner_id,name,cidr,revision,policy,created_at) VALUES(?,?,?,?,1,?,?)", id, u.ID, n.Name, n.CIDR, n.Policy, now()); e != nil {
			return e
		}
		return audit(tx, u.ID, "network.create", id)
	})
	if e != nil {
		return e
	}
	return write(w, 201, n)
}
func (s *Service) invite(w http.ResponseWriter, r *http.Request) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	var v struct {
		TTL int `json:"ttl_seconds"`
	}
	if e = decode(w, r, &v); e != nil {
		return e
	}
	if v.TTL < 60 || v.TTL > 86400 {
		return failure(400, "invite TTL must be 60–86400 seconds")
	}
	token, e := random(32)
	if e != nil {
		return e
	}
	expires := now() + int64(v.TTL)
	id := r.PathValue("id")
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		if _, e := network(tx, id, u); e != nil {
			return e
		}
		if _, e := tx.Exec("INSERT INTO invites(hash,network_id,expires) VALUES(?,?,?)", digest(token), id, expires); e != nil {
			return e
		}
		return audit(tx, u.ID, "invite.create", id)
	})
	if e != nil {
		return e
	}
	return write(w, 201, map[string]any{"invite": token, "expires": expires})
}
func scanDevice(row interface{ Scan(...any) error }) (Device, error) {
	var d Device
	e := row.Scan(&d.ID, &d.NetworkID, &d.Name, &d.IP, &d.Status, &d.LastSeen)
	return d, e
}

const deviceCols = "id,network_id,name,coalesce(ip,''),status,coalesce(last_seen,0)"

func (s *Service) devices(w http.ResponseWriter, r *http.Request) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	id := r.PathValue("id")
	out := []Device{}
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		if _, e := network(tx, id, u); e != nil {
			return e
		}
		rows, e := tx.Query("SELECT "+deviceCols+" FROM devices WHERE network_id=? ORDER BY created_at,id", id)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			d, e := scanDevice(rows)
			if e != nil {
				return e
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if e != nil {
		return e
	}
	return write(w, 200, out)
}
func (s *Service) enroll(w http.ResponseWriter, r *http.Request) error {
	var v Enrollment
	if e := decode(w, r, &v); e != nil {
		return e
	}
	if !v.Verify() {
		return failure(400, "invalid enrollment proof")
	}
	id, e := random(18)
	if e != nil {
		return e
	}
	var d Device
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		var nid string
		e := tx.QueryRow("SELECT network_id FROM invites WHERE hash=? AND used_at IS NULL AND expires>?", digest(v.Invite), now()).Scan(&nid)
		if errors.Is(e, sql.ErrNoRows) {
			return failure(403, "invite invalid or expired")
		}
		if e != nil {
			return e
		}
		var count int
		if e = tx.QueryRow("SELECT count(*) FROM devices WHERE network_id=?", nid).Scan(&count); e != nil {
			return e
		}
		if count >= 128 {
			return failure(409, "device quota exhausted")
		}
		if e = tx.QueryRow("SELECT count(*) FROM devices WHERE identity=? OR (network_id=? AND wg_key=?)", v.Identity, nid, v.WGKey).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return failure(409, "identity or WireGuard key already enrolled")
		}
		if _, e = tx.Exec("UPDATE invites SET used_at=? WHERE hash=?", now(), digest(v.Invite)); e != nil {
			return e
		}
		if _, e = tx.Exec("INSERT INTO devices(id,network_id,name,identity,wg_key,status,created_at) VALUES(?,?,?,?,?,'pending',?)", id, nid, v.Name, v.Identity, v.WGKey, now()); e != nil {
			return e
		}
		d = Device{ID: id, NetworkID: nid, Name: v.Name, Status: "pending"}
		return audit(tx, id, "device.enroll", id)
	})
	if e != nil {
		return e
	}
	return write(w, 201, d)
}
func (s *Service) approve(w http.ResponseWriter, r *http.Request) error {
	return s.changeDevice(w, r, true)
}
func (s *Service) revoke(w http.ResponseWriter, r *http.Request) error {
	return s.changeDevice(w, r, false)
}
func (s *Service) changeDevice(w http.ResponseWriter, r *http.Request, approve bool) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	nid, id := r.PathValue("id"), r.PathValue("device")
	var d Device
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		n, e := network(tx, nid, u)
		if e != nil {
			return e
		}
		d, e = scanDevice(tx.QueryRow("SELECT "+deviceCols+" FROM devices WHERE id=? AND network_id=?", id, nid))
		if e != nil {
			return e
		}
		if approve {
			if d.Status != "pending" {
				return failure(409, "only pending device may be approved")
			}
			ip, e := allocate(tx, nid, n.CIDR)
			if e != nil {
				return e
			}
			d.IP = ip
			d.Status = "approved"
			if _, e = tx.Exec("UPDATE devices SET status=?,ip=? WHERE id=?", d.Status, d.IP, id); e != nil {
				return e
			}
		} else {
			if d.Status == "revoked" {
				return nil
			}
			d.Status = "revoked"
			if _, e = tx.Exec("DELETE FROM exit_grants WHERE client_id=? OR gateway_id=?", id, id); e != nil {
				return e
			}
			if _, e = tx.Exec("DELETE FROM subnet_routes WHERE device_id=?", id); e != nil {
				return e
			}
			if _, e = tx.Exec("DELETE FROM dns_aliases WHERE device_id=?", id); e != nil {
				return e
			}
			if _, e = tx.Exec("DELETE FROM traffic_rules WHERE a=? OR b=?", id, id); e != nil {
				return e
			}
			if _, e = tx.Exec("UPDATE devices SET status='revoked' WHERE id=?", id); e != nil {
				return e
			}
		}
		if _, e = tx.Exec("DELETE FROM pair_relays WHERE network_id=? AND (a IN (SELECT id FROM devices WHERE network_id=? AND status<>'approved') OR b IN (SELECT id FROM devices WHERE network_id=? AND status<>'approved'))", nid, nid, nid); e != nil {
			return e
		}
		if _, e = tx.Exec("UPDATE networks SET revision=revision+1 WHERE id=?", nid); e != nil {
			return e
		}
		return audit(tx, u.ID, "device."+d.Status, id)
	})
	if e != nil {
		return e
	}
	return write(w, 200, d)
}
func (s *Service) policy(w http.ResponseWriter, r *http.Request) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	var v struct {
		Policy string `json:"policy"`
	}
	if e = decode(w, r, &v); e != nil {
		return e
	}
	if v.Policy != "allow_members" && v.Policy != "deny_members" {
		return failure(400, "invalid policy")
	}
	id := r.PathValue("id")
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		if _, e := network(tx, id, u); e != nil {
			return e
		}
		if _, e := tx.Exec("DELETE FROM pair_relays WHERE network_id=?", id); e != nil {
			return e
		}
		if _, e := tx.Exec("UPDATE networks SET policy=?,revision=revision+1 WHERE id=?", v.Policy, id); e != nil {
			return e
		}
		return audit(tx, u.ID, "policy.update", id)
	})
	if e != nil {
		return e
	}
	return write(w, 200, map[string]bool{"ok": true})
}
func (s *Service) rules(w http.ResponseWriter, r *http.Request) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	nid := r.PathValue("id")
	out := []Rule{}
	e = withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		if _, e := network(tx, nid, u); e != nil {
			return e
		}
		rows, e := tx.Query("SELECT a,b,allow FROM pair_rules WHERE network_id=? ORDER BY a,b", nid)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v Rule
			if e = rows.Scan(&v.A, &v.B, &v.Allow); e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if e != nil {
		return e
	}
	return write(w, 200, out)
}
func (s *Service) setRule(w http.ResponseWriter, r *http.Request) error {
	u, e := s.user(r)
	if e != nil {
		return e
	}
	var v Rule
	if e = decode(w, r, &v); e != nil {
		return e
	}
	if v.A == v.B || v.A == "" || v.B == "" {
		return failure(400, "two different devices required")
	}
	if v.A > v.B {
		v.A, v.B = v.B, v.A
	}
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
		if _, e := tx.Exec("INSERT INTO pair_rules VALUES(?,?,?,?) ON CONFLICT(network_id,a,b) DO UPDATE SET allow=excluded.allow", nid, v.A, v.B, v.Allow); e != nil {
			return e
		}
		if !v.Allow {
			if _, e := tx.Exec("DELETE FROM pair_relays WHERE network_id=? AND a=? AND b=?", nid, v.A, v.B); e != nil {
				return e
			}
		}
		if _, e := tx.Exec("UPDATE networks SET revision=revision+1 WHERE id=?", nid); e != nil {
			return e
		}
		return audit(tx, u.ID, "rule.update", nid)
	})
	if e != nil {
		return e
	}
	return write(w, 200, v)
}
func (s *Service) auditList(w http.ResponseWriter, r *http.Request) error {
	if _, e := s.admin(r); e != nil {
		return e
	}
	rows, e := s.Store.DB.QueryContext(r.Context(), "SELECT actor,action,target,at FROM audit ORDER BY id DESC LIMIT 100")
	if e != nil {
		return e
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var a, b, c string
		var ts int64
		if e = rows.Scan(&a, &b, &c, &ts); e != nil {
			return e
		}
		out = append(out, map[string]any{"actor": a, "action": b, "target": c, "at": ts})
	}
	if e = rows.Err(); e != nil {
		return e
	}
	return write(w, 200, out)
}
func (s *Service) snapshot(w http.ResponseWriter, r *http.Request) error {
	var v DeviceRequest
	if e := decode(w, r, &v); e != nil {
		return e
	}
	var out Snapshot
	e := withTx(r.Context(), s.Store, func(tx *sql.Tx) error {
		var identity string
		d, e := scanDevice(tx.QueryRow("SELECT "+deviceCols+" FROM devices WHERE id=?", v.ID))
		if errors.Is(e, sql.ErrNoRows) {
			return failure(401, "unknown device")
		}
		if e != nil {
			return e
		}
		if e = tx.QueryRow("SELECT identity FROM devices WHERE id=?", v.ID).Scan(&identity); e != nil {
			return e
		}
		if !v.Verify(identity) {
			return failure(401, "invalid device proof")
		}
		t := now()
		if _, e = tx.Exec("DELETE FROM nonces WHERE expires<=?", t); e != nil {
			return e
		}
		res, e := tx.Exec("INSERT OR IGNORE INTO nonces VALUES(?,?,?)", d.ID, v.Nonce, t+90)
		if e != nil {
			return e
		}
		affected, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if affected != 1 {
			return failure(409, "replayed request")
		}
		if _, e = tx.Exec("UPDATE devices SET last_seen=? WHERE id=?", t, d.ID); e != nil {
			return e
		}
		d.LastSeen = t
		var rev int64
		var policy string
		if e = tx.QueryRow("SELECT revision,policy FROM networks WHERE id=?", d.NetworkID).Scan(&rev, &policy); e != nil {
			return e
		}
		out = Snapshot{Device: d, Revision: rev, ValidUntil: t + 20, Peers: []Peer{}}
		if d.Status != "approved" {
			return nil
		}
		advanced, traffic, e := advancedFor(tx, d.NetworkID)
		if e != nil {
			return e
		}
		grants, e := exitFor(tx, d.NetworkID)
		if e != nil {
			return e
		}
		if len(grants) > 0 && !v.ExitRoutes {
			return failure(426, "exit policies require M6.1 Agent")
		}
		if !v.Advanced && (len(advanced) > 0 || len(traffic) > 0) {
			return failure(426, "advanced network policy requires M6 agent")
		}
		out.Exports = advanced[d.ID].Subnets
		out.DNSLabel = advanced[d.ID].DNSLabel
		if e = s.recordProbes(tx, d, v.Probes); e != nil {
			return e
		}
		nodes, e := s.eligible(tx, d.NetworkID)
		if e != nil {
			return e
		}
		if len(nodes) > 0 && !v.MultiRelay {
			return failure(426, "registered relay nodes require M5 agent")
		}
		if v.MultiRelay {
			for _, n := range nodes {
				out.Nodes = append(out.Nodes, n.RelayNode)
			}
		}
		out.RelayURL = s.RelayURL
		out.STUNURL = s.STUNURL
		rows, e := tx.Query("SELECT id,name,ip,wg_key,identity FROM devices WHERE network_id=? AND status='approved' AND id<>? ORDER BY id", d.NetworkID, d.ID)
		if e != nil {
			return e
		}
		type candidate struct {
			peer     Peer
			identity string
		}
		var cs []candidate
		for rows.Next() {
			var c candidate
			if e = rows.Scan(&c.peer.ID, &c.peer.Name, &c.peer.IP, &c.peer.WGKey, &c.identity); e != nil {
				rows.Close()
				return e
			}
			cs = append(cs, c)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		// Same pair, revision and two-minute epoch => deterministic token on both ends.
		epoch := t / 120
		expires := (epoch+1)*120 + 30
		for _, c := range cs {
			a, b := d.ID, c.peer.ID
			if a > b {
				a, b = b, a
			}
			allow := policy == "allow_members"
			var override bool
			e = tx.QueryRow("SELECT allow FROM pair_rules WHERE network_id=? AND a=? AND b=?", d.NetworkID, a, b).Scan(&override)
			if e == nil {
				allow = override
			} else if !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if !allow {
				continue
			}
			selected, e := s.chooseNode(tx, d.NetworkID, a, b, nodes)
			if e != nil {
				return e
			}
			if selected.ID == "" {
				continue
			}
			if g, ok := grants[d.ID]; ok && g.Gateway == c.peer.ID {
				c.peer.ExitTargets = g.Targets
			}
			if g, ok := grants[c.peer.ID]; ok && g.Gateway == d.ID {
				c.peer.ExitServed = g.Targets
			}
			c.peer.Subnets = advanced[c.peer.ID].Subnets
			c.peer.DNSLabel = advanced[c.peer.ID].DNSLabel
			c.peer.Traffic = traffic[[2]string{a, b}]
			c.peer.RelayNode = selected.ID
			c.peer.RelayURL = selected.RelayURL
			c.peer.STUNURL = selected.STUNURL
			ids := []string{identity, c.identity}
			sort.Strings(ids)
			flow := digest(d.NetworkID + ":" + a + ":" + b + ":" + intString(rev) + ":" + intString(epoch))
			c.peer.Lease, e = relay.Issue(s.Issuer, relay.Lease{Node: selected.ID, Network: d.NetworkID, Flow: flow, A: ids[0], B: ids[1], Expires: expires})
			if e != nil {
				return e
			}
			out.Peers = append(out.Peers, c.peer)
		}
		return nil
	})
	if e != nil {
		return e
	}
	return write(w, 200, out)
}
func intString(i int64) string { b, _ := json.Marshal(i); return string(b) }

// AuthorizeLease checks current membership, policy and shared pair assignment.
func (s *Service) AuthorizeLease(l relay.Lease) bool { return s.authorizeCurrent(l) }
