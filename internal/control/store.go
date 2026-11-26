package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

const schema = `
CREATE TABLE users(id TEXT PRIMARY KEY, login TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','member')), created_at INTEGER NOT NULL);
CREATE TABLE sessions(hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
CREATE TABLE networks(id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL, cidr TEXT NOT NULL UNIQUE, revision INTEGER NOT NULL DEFAULT 1, policy TEXT NOT NULL CHECK(policy IN ('allow_members','deny_members')), created_at INTEGER NOT NULL);
CREATE TABLE invites(hash TEXT PRIMARY KEY, network_id TEXT NOT NULL REFERENCES networks(id), expires INTEGER NOT NULL, used_at INTEGER);
CREATE TABLE devices(id TEXT PRIMARY KEY, network_id TEXT NOT NULL REFERENCES networks(id), name TEXT NOT NULL, identity TEXT NOT NULL UNIQUE, wg_key TEXT NOT NULL, ip TEXT, status TEXT NOT NULL CHECK(status IN ('pending','approved','revoked')), created_at INTEGER NOT NULL, last_seen INTEGER, UNIQUE(network_id,wg_key), UNIQUE(network_id,ip));
CREATE TABLE pair_rules(network_id TEXT NOT NULL REFERENCES networks(id), a TEXT NOT NULL REFERENCES devices(id), b TEXT NOT NULL REFERENCES devices(id), allow INTEGER NOT NULL CHECK(allow IN (0,1)), PRIMARY KEY(network_id,a,b), CHECK(a<b));
CREATE TABLE nonces(device_id TEXT NOT NULL REFERENCES devices(id), nonce TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(device_id,nonce));
CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX idx_device_network ON devices(network_id,status);
CREATE INDEX idx_nonce_expiry ON nonces(expires);
PRAGMA user_version=1;
`

type Store struct{ DB *sql.DB }

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path required")
	}
	path, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	st, e := os.Lstat(path)
	if os.IsNotExist(e) {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, e
		}
		if e = f.Close(); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	} else if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("database must be a regular 0600 file")
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: "_foreign_keys=on&_busy_timeout=5000&_journal_mode=WAL&_txlock=immediate"}
	db, e := sql.Open("sqlite3", u.String())
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	fail := func(e error) (*Store, error) { db.Close(); return nil, e }
	tx, e := db.Begin()
	if e != nil {
		return fail(e)
	}
	var v int
	migrate := func() error {
		if e := tx.QueryRow("PRAGMA user_version").Scan(&v); e != nil {
			return e
		}
		if v < 0 || v > 6 {
			return fmt.Errorf("unsupported database schema %d", v)
		}
		for _, m := range []struct {
			version int
			sql     string
		}{{1, schema}, {2, schemaV2}, {3, schemaV3}, {4, schemaV4}, {5, schemaV5}, {6, schemaV6}} {
			if v < m.version {
				if _, e := tx.Exec(m.sql); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if e = migrate(); e != nil {
		tx.Rollback()
		return fail(e)
	}
	if e = tx.Commit(); e != nil {
		return fail(e)
	}
	return &Store{db}, nil
}
func (s *Store) Close() error { return s.DB.Close() }
func now() int64              { return time.Now().Unix() }
func random(n int) (string, error) {
	b := make([]byte, n)
	_, e := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), e
}
func digest(s string) string    { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func loginName(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func validLogin(s string) bool {
	if len(s) < 3 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == '@') {
			return false
		}
	}
	return true
}
func passwordHash(p string) (string, error) {
	if len(p) < 12 || len(p) > 256 {
		return "", errors.New("password must be 12–256 bytes")
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	h := argon2.IDKey([]byte(p), salt, 3, 64*1024, 2, 32)
	return base64.RawStdEncoding.EncodeToString(salt) + "." + base64.RawStdEncoding.EncodeToString(h), nil
}
func checkPassword(p, hash string) bool {
	if len(p) > 256 {
		return false
	}
	parts := strings.Split(hash, ".")
	if len(parts) != 2 {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(parts[0])
	if e != nil || len(salt) != 16 {
		return false
	}
	h, e := base64.RawStdEncoding.DecodeString(parts[1])
	if e != nil || len(h) != 32 {
		return false
	}
	return subtle.ConstantTimeCompare(h, argon2.IDKey([]byte(p), salt, 3, 64*1024, 2, 32)) == 1
}
func PasswordFile(path string) (string, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return "", e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 512 {
		return "", errors.New("password file must be a small regular 0600 file")
	}
	b, e := os.ReadFile(path)
	return strings.TrimRight(string(b), "\r\n"), e
}

type User struct {
	ID    string `json:"id"`
	Login string `json:"login"`
	Role  string `json:"role"`
}

func (s *Store) Bootstrap(login, password string) error {
	login = loginName(login)
	if !validLogin(login) {
		return errors.New("invalid login")
	}
	h, e := passwordHash(password)
	if e != nil {
		return e
	}
	id, e := random(18)
	if e != nil {
		return e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var count int
	if e = tx.QueryRow("SELECT count(*) FROM users").Scan(&count); e != nil {
		return e
	}
	if count != 0 {
		return errors.New("administrator already initialized")
	}
	if _, e = tx.Exec("INSERT INTO users VALUES(?,?,?,?,?)", id, login, h, "admin", now()); e != nil {
		return e
	}
	if e = audit(tx, id, "bootstrap", id); e != nil {
		return e
	}
	return tx.Commit()
}
func audit(tx *sql.Tx, actor, action, target string) error {
	_, e := tx.Exec("INSERT INTO audit(actor,action,target,at) VALUES(?,?,?,?)", actor, action, target, now())
	return e
}
func withTx(ctx context.Context, s *Store, fn func(*sql.Tx) error) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = fn(tx); e != nil {
		return e
	}
	return tx.Commit()
}
func prefix(s string) (netip.Prefix, error) {
	p, e := netip.ParsePrefix(s)
	if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 24 || p.Bits() > 28 || !p.Addr().IsPrivate() {
		return netip.Prefix{}, errors.New("CIDR must be canonical private IPv4 /24–/28")
	}
	return p, nil
}
func allocate(tx *sql.Tx, nid, cidr string) (string, error) {
	p, e := prefix(cidr)
	if e != nil {
		return "", e
	}
	rows, e := tx.Query("SELECT ip FROM devices WHERE network_id=? AND ip IS NOT NULL", nid)
	if e != nil {
		return "", e
	}
	used := map[string]bool{}
	for rows.Next() {
		var ip string
		if e = rows.Scan(&ip); e != nil {
			rows.Close()
			return "", e
		}
		used[ip] = true
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return "", e
	}
	// Cap total assigned identities at 64 to fit bounded peer lists. Never reuse revoked IPs.
	if len(used) >= 64 {
		return "", failure(409, "network address quota exhausted")
	}
	for a := p.Addr().Next(); p.Contains(a) && p.Contains(a.Next()); a = a.Next() {
		if !used[a.String()] {
			return a.String(), nil
		}
	}
	return "", failure(409, "network address pool exhausted")
}
