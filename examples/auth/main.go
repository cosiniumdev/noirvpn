// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Command auth is an example controller for the noirvpn control bus.
//
// It decides the logins of a server that runs with `auth-external`. For each
// waiting session it reads the user name and password once (`auth.credentials`),
// checks them against a small table in this file, and responds with
// `auth.decide`.
//
// Example code:
//   - the users are in the source
//   - the passwords are plain SHA-256; a real controller must use a slow
//     password hash such as argon2id or bcrypt
//
// Run it as its own user with only the `auth` role, for example
// `bus-allow uid noirauth auth` in the server config.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.nanomsg.org/mangos/v3"
	"go.nanomsg.org/mangos/v3/protocol/req"
	"go.nanomsg.org/mangos/v3/protocol/sub"

	// Registers the ipc:// transport. The bus uses this transport only.
	_ "go.nanomsg.org/mangos/v3/transport/ipc"
)

// account is one user that may log in.
type account struct {
	hash   string   // SHA-256 of the password, lower-case hex
	locked bool     // the login is always refused
	push   []string // extra push lines for this user, sent with "allow"
}

// accounts is the user table. The passwords are random test values (see
// README.md). Create a new entry with `auth -hash`.
var accounts = map[string]account{
	"alice": {hash: "3092227d1aa7a815c1f09442ac5ebb91c0ef717e17c7d6213b447cc478dcc36a"},
	"bob":   {hash: "c6f01cd6f2a59dca931485391a0a92106d13dba1389b0cdeb980184cdc1731bd"},
	// carol gets a fixed tunnel address and one more route. The daemon checks
	// every push line and refuses the whole decision if one line is bad.
	"carol": {
		hash: "e7e02006fb3bc01fcc06b5d7c766481dfc64d647c4be769156e951d8f1a3b73d",
		push: []string{
			"ifconfig-push 10.8.0.50 255.255.255.0",
			"route 192.168.5.0 255.255.255.0",
		},
	},
	"dave": {hash: "040db1ad121666b1fe7582180c0e90ca54515ce890723cde65bc4c73abc53ea1", locked: true},
}

// dummyHash is compared when the user is not in the table. Then an unknown
// user takes the same time as a wrong password.
var dummyHash = sha256.Sum256([]byte("no such user"))

// Settings from the command line.
var (
	flagName      = flag.String("name", "server", "instance name of the server daemon")
	flagDir       = flag.String("dir", "", "socket directory (default: /run/noirvpn, then the user's own)")
	flagTimeout   = flag.Duration("timeout", 5*time.Second, "send and receive timeout of one request")
	flagMatchName = flag.Bool("match-name", true, "refuse a user name that differs from the client identity")
	flagHash      = flag.Bool("hash", false, "read a password on stdin, print its SHA-256 and exit")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)

	if *flagHash {
		printHash()
		return
	}

	b := newBus(*flagName, *flagDir, *flagTimeout)
	log.Printf("control %s, events %s", b.control, b.events)

	// A stop is safe at any time: a session that waits gets no response and
	// the daemon denies it at its deadline.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Printf("stop on %v", s)
		os.Exit(0)
	}()

	c := newController(b)
	for {
		err := c.follow()
		log.Printf("event stream: %v; start again in 2 s", err)
		time.Sleep(2 * time.Second)
	}
}

// printHash reads one line from stdin and prints the SHA-256 of it, for a new
// entry in the accounts table.
func printHash() {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		log.Fatalf("read password: %v", err)
	}
	sum := sha256.Sum256([]byte(strings.TrimRight(line, "\r\n")))
	fmt.Println(hex.EncodeToString(sum[:]))
}

// ---------------------------------------------------------------- the bus

// bus holds the two socket URLs of one daemon.
type bus struct {
	control string // REQ: requests and replies
	events  string // SUB: the event stream
	timeout time.Duration
}

// busError is an error reply of the daemon. Programs use Code; Message is
// for people.
type busError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *busError) Error() string { return e.Code + ": " + e.Message }

// errTimeout means no reply came in time. The request may still be applied.
var errTimeout = errors.New("no reply in time")

func newBus(name, dir string, timeout time.Duration) *bus {
	if dir == "" {
		dir = findDir(name)
	}
	return &bus{
		control: "ipc://" + filepath.Join(dir, name+".control"),
		events:  "ipc://" + filepath.Join(dir, name+".events"),
		timeout: timeout,
	}
}

// findDir returns the directory of the daemon's sockets: /run/noirvpn for a
// daemon that runs as root, else $XDG_RUNTIME_DIR/noirvpn, or /tmp/noirvpn-<uid>.
func findDir(name string) string {
	system := "/run/noirvpn"
	if runtime.GOOS == "darwin" {
		system = "/var/run/noirvpn"
	}
	if _, err := os.Stat(filepath.Join(system, name+".control")); err == nil {
		return system
	}
	if x := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(x) {
		return filepath.Join(x, "noirvpn")
	}
	return fmt.Sprintf("/tmp/noirvpn-%d", os.Getuid())
}

// newID returns a request id of 32 random hex digits.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// request encodes one request. The bytes are kept: a repeat after a timeout
// must send the same id and the same bytes.
func request(op string, args map[string]any) (id string, body []byte) {
	id = newID()
	msg := map[string]any{"v": 1, "id": id, "op": op}
	// A nil map encodes as null, and the daemon refuses that. A missing
	// `args` means {}.
	if args != nil {
		msg["args"] = args
	}
	body, err := json.Marshal(msg)
	if err != nil {
		panic(err)
	}
	return id, body
}

// send sends one request and returns the result object of the reply.
//
// It opens a new REQ socket for each request. A REQ socket handles one request
// at a time, and a new socket keeps the goroutines apart.
func (b *bus) send(id string, body []byte) (json.RawMessage, error) {
	sock, err := req.NewSocket()
	if err != nil {
		return nil, err
	}
	defer sock.Close()

	// Without deadlines a REQ socket can wait for ever.
	_ = sock.SetOption(mangos.OptionSendDeadline, b.timeout)
	_ = sock.SetOption(mangos.OptionRecvDeadline, b.timeout)
	// Resends are up to this code: it decides when to repeat a request.
	_ = sock.SetOption(mangos.OptionRetryTime, time.Duration(0))
	// A peers.list reply can be large.
	_ = sock.SetOption(mangos.OptionMaxRecvSize, 8<<20)

	// The dial fails at once when the socket file does not exist: the
	// daemon is not running.
	if err := sock.Dial(b.control); err != nil {
		return nil, fmt.Errorf("dial %s: %w", b.control, err)
	}
	if err := sock.Send(body); err != nil {
		if errors.Is(err, mangos.ErrSendTimeout) {
			return nil, errTimeout
		}
		return nil, err
	}
	raw, err := sock.Recv()
	if err != nil {
		if errors.Is(err, mangos.ErrRecvTimeout) {
			return nil, errTimeout
		}
		return nil, err
	}

	var reply struct {
		ID     *string         `json:"id"`
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *busError       `json:"error"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, fmt.Errorf("bad reply: %w", err)
	}
	// The id is null when the daemon refused the request before it read it.
	if reply.ID != nil && *reply.ID != id {
		return nil, errors.New("the reply is for another request")
	}
	if !reply.OK {
		if reply.Error == nil {
			return nil, errors.New("error reply without an error object")
		}
		return nil, reply.Error
	}
	return reply.Result, nil
}

// call sends a read request or a one-shot request. It is never repeated.
func (b *bus) call(op string, args map[string]any) (json.RawMessage, error) {
	id, body := request(op, args)
	return b.send(id, body)
}

// callRetry sends a request that changes state. After a lost reply, a `timeout`
// or a `busy` it sends the same bytes again. The daemon knows the id, so a
// request that already ran gets its stored reply and runs once.
func (b *bus) callRetry(op string, args map[string]any) (json.RawMessage, error) {
	id, body := request(op, args)
	var err error
	for try := 1; try <= 3; try++ {
		var res json.RawMessage
		res, err = b.send(id, body)
		var be *busError
		switch {
		case err == nil:
			return res, nil
		case errors.Is(err, errTimeout):
		case errors.As(err, &be) && (be.Code == "timeout" || be.Code == "busy"):
		default:
			return nil, err
		}
		log.Printf("%s: %v (try %d of 3)", op, err, try)
		time.Sleep(time.Duration(try) * 500 * time.Millisecond)
	}
	return nil, err
}

// ------------------------------------------------------------- the events

// envelope is one event. The fields that this program does not use are left
// out; unknown fields must be ignored anyway.
type envelope struct {
	V     int             `json:"v"`
	Run   string          `json:"run"`
	Seq   uint64          `json:"seq"`
	Topic string          `json:"topic"`
	Data  json.RawMessage `json:"data"`
}

// waiting is the part of a peer.auth_pending event (or of a peer object)
// that the controller needs. All strings come from the network.
type waiting struct {
	Session  string  `json:"session"`
	Name     *string `json:"name"` // null while the identity is not known
	RealAddr string  `json:"real_addr"`
	State    string  `json:"state"` // only in a peer object
}

// controller decides the waiting sessions.
type controller struct {
	bus *bus

	mu     sync.Mutex
	active map[string]bool // sessions with a running decision
	slots  chan struct{}   // limits the decisions that run at once
}

func newController(b *bus) *controller {
	return &controller{
		bus:    b,
		active: map[string]bool{},
		// The daemon queues few requests (max_pending) and responds with `busy`
		// above that. Keep well below it.
		slots: make(chan struct{}, 4),
	}
}

// follow reads the event stream until an error, a gap or a daemon restart.
func (c *controller) follow() error {
	// 1. Subscribe to everything, then connect. The library filters no
	//    topic: a filter in nng causes false gaps in the sequence numbers.
	sock, err := sub.NewSocket()
	if err != nil {
		return err
	}
	defer sock.Close()
	_ = sock.SetOption(mangos.OptionSubscribe, []byte(""))
	_ = sock.SetOption(mangos.OptionRecvDeadline, time.Second)
	if err := sock.Dial(c.bus.events); err != nil {
		return fmt.Errorf("dial %s: %w", c.bus.events, err)
	}

	// 2. Take a snapshot: the daemon's run id and last sequence number.
	raw, err := c.bus.call("status", nil)
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	var st struct {
		Mode string `json:"mode"`
		Bus  struct {
			Run string `json:"run"`
			Seq uint64 `json:"seq"`
		} `json:"bus"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if st.Mode != "server" {
		return fmt.Errorf("the daemon is a %s; auth-external is a server option", st.Mode)
	}
	run, last := st.Bus.Run, st.Bus.Seq
	log.Printf("following run %s from seq %d", run, last)

	// Sessions that started to wait before this point have no event in
	// the stream. Find them in the peer list.
	if err := c.decideListed(); err != nil {
		return fmt.Errorf("peers.list: %w", err)
	}

	// 3. Read the events. Each one must have the next sequence number.
	for {
		msg, err := sock.Recv()
		if errors.Is(err, mangos.ErrRecvTimeout) {
			continue
		}
		if err != nil {
			return err
		}

		// A message is "<topic> <json>". The topic has no space.
		topic, body, ok := strings.Cut(string(msg), " ")
		if !ok {
			continue
		}
		var ev envelope
		if json.Unmarshal([]byte(body), &ev) != nil || ev.Topic != topic {
			continue
		}

		// 4. A new run id is a daemon restart. A jump in seq means lost
		//    events. Both need a new snapshot.
		if ev.Run != run {
			return errors.New("the daemon restarted")
		}
		if ev.Seq <= last {
			continue // already in the snapshot
		}
		if ev.Seq != last+1 {
			return fmt.Errorf("events %d to %d were lost", last+1, ev.Seq-1)
		}
		last = ev.Seq

		if ev.Topic == "peer.auth_pending" {
			var w waiting
			if json.Unmarshal(ev.Data, &w) == nil && w.Session != "" {
				c.start(w)
			}
		}
	}
}

// decideListed starts a decision for every session in the peer list that
// waits for one. `all` includes the sessions that are not active yet.
func (c *controller) decideListed() error {
	offset := 0
	for {
		raw, err := c.bus.call("peers.list", map[string]any{"all": true, "limit": 500, "offset": offset})
		if err != nil {
			return err
		}
		var page struct {
			Count int       `json:"count"`
			Peers []waiting `json:"peers"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, p := range page.Peers {
			if p.State == "auth_pending" {
				c.start(p)
			}
		}
		offset += len(page.Peers)
		if len(page.Peers) == 0 || offset >= page.Count {
			return nil
		}
	}
}

// start runs the decision for one session in its own goroutine. The event
// reader must stay fast, or the daemon drops events for this subscriber.
func (c *controller) start(w waiting) {
	c.mu.Lock()
	if c.active[w.Session] {
		// The snapshot and the stream can both report one session.
		c.mu.Unlock()
		return
	}
	c.active[w.Session] = true
	c.mu.Unlock()

	go func() {
		c.slots <- struct{}{}
		defer func() {
			<-c.slots
			c.mu.Lock()
			delete(c.active, w.Session)
			c.mu.Unlock()
		}()
		c.decide(w)
	}()
}

// -------------------------------------------------------------- decisions

// decide reads the credentials of one session and sends the decision.
func (c *controller) decide(w waiting) {
	// The password is in this reply only. The daemon wipes it when it sends the
	// reply, so a second call gets null. The request is not repeated: if the reply
	// is lost, the only safe response is a deny, and the client logs in again.
	raw, err := c.bus.call("auth.credentials", map[string]any{"session": w.Session})
	var be *busError
	if errors.As(err, &be) && (be.Code == "not_found" || be.Code == "conflict") {
		// The session ended, or someone else decided it.
		log.Printf("session %q: %s", w.Session, be.Code)
		return
	}
	if err != nil {
		log.Printf("session %q: auth.credentials: %v", w.Session, err)
		c.send(w.Session, "deny", "the login could not be checked", nil)
		return
	}
	var cred struct {
		Username *string `json:"username"`
		Password *string `json:"password"`
	}
	if err := json.Unmarshal(raw, &cred); err != nil {
		log.Printf("session %q: auth.credentials: %v", w.Session, err)
		c.send(w.Session, "deny", "the login could not be checked", nil)
		return
	}

	user := ""
	if cred.Username != nil {
		user = *cred.Username
	}
	password := ""
	if cred.Password != nil {
		password = *cred.Password
	}
	// Go cannot wipe a string from memory. Keep the password in this
	// function only, and never log it.
	ok, reason, push := check(user, password, w.Name)

	// Text from the client is printed with %q, so control characters
	// cannot change the log.
	if ok {
		log.Printf("session %q: allow user %q from %q", w.Session, user, w.RealAddr)
		c.send(w.Session, "allow", "", push)
	} else {
		log.Printf("session %q: deny user %q from %q: %s", w.Session, user, w.RealAddr, reason)
		c.send(w.Session, "deny", reason, nil)
	}
}

// check decides one login. The reason goes to the client, so it does not
// say whether the user name or the password was wrong.
func check(user, password string, name *string) (ok bool, reason string, push []string) {
	const wrong = "wrong user name or password"

	acct, known := accounts[user]
	want := dummyHash[:]
	if known {
		if h, err := hex.DecodeString(acct.hash); err == nil {
			want = h
		}
	}
	got := sha256.Sum256([]byte(password))
	// A constant time compare does not show by its run time how many bytes
	// of the hash were right.
	match := subtle.ConstantTimeCompare(got[:], want) == 1

	switch {
	case !known || !match:
		return false, wrong, nil
	case *flagMatchName && name != nil && *name != user:
		// With key pinning the daemon ensures the two are the same. In CA mode `name`
		// is the certificate common name: this stops a user from logging in with another
		// user's certificate.
		return false, wrong, nil
	case acct.locked:
		return false, "account locked", nil
	}
	return true, "", acct.push
}

// send sends one auth.decide request.
func (c *controller) send(session, decision, reason string, push []string) {
	args := map[string]any{"session": session, "decision": decision}
	if reason != "" {
		args["reason"] = reason
	}
	if len(push) > 0 {
		args["push"] = push
	}
	if _, err := c.bus.callRetry("auth.decide", args); err != nil {
		// not_found: the client left. conflict: the session timed out
		// or was decided already. bad_request: a push line was refused.
		log.Printf("session %q: auth.decide %s: %v", session, decision, err)
	}
}
