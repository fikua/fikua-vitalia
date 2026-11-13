// Command sendhook posts a signed test webhook to a running instance, to
// check a deployment end to end: TLS, routing and the shared secret.
//
//	VITALIA_WEBHOOK_SECRET=... sendhook -url https://vitalia.fikua.com/webhooks/enrollments
//	VITALIA_WEBHOOK_SECRET=... sendhook -url ... -bad     # expects 401
//
// The secret is read from the environment, never from a flag, so it does
// not end up in the shell history.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/fikua/fikua-vitalia/internal/cgcom"
)

func main() {
	url := flag.String("url", "", "webhook URL of the running instance (required)")
	bad := flag.Bool("bad", false, "sign with a wrong secret; the instance must answer 401")
	enrollmentID := flag.String("enrollment", "", "enrollment id (default: a random one, stored as unknown)")
	state := flag.String("state", string(cgcom.PendingConfirmation), "enrollment state in the body")
	flag.Parse()

	secret := os.Getenv("VITALIA_WEBHOOK_SECRET")
	if *url == "" || secret == "" {
		fmt.Fprintln(os.Stderr, "usage: VITALIA_WEBHOOK_SECRET=... sendhook -url <webhook url> [-bad] [-enrollment id] [-state STATE]")
		os.Exit(2)
	}
	if *bad {
		secret = "this-is-not-the-secret-of-the-platform"
	}
	id := *enrollmentID
	if id == "" {
		id = uuid()
	}
	now := time.Now().UTC()
	ev := cgcom.Event{
		EventID: uuid(), Event: cgcom.EventStateChanged, OccurredAt: now,
		Enrollment: cgcom.Enrollment{ID: id, State: cgcom.State(*state), CollegiateNumber: "000000000", UpdatedAt: &now},
	}
	body, _ := json.Marshal(ev)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	status, resp, err := cgcom.Send(ctx, &http.Client{}, *url, []byte(secret), body, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("event_id=%s enrollment=%s -> HTTP %d %s\n", ev.EventID, id, status, resp)

	want2xx := !*bad
	if (status >= 200 && status < 300) != want2xx {
		fmt.Fprintln(os.Stderr, "unexpected status")
		os.Exit(1)
	}
}

func uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
