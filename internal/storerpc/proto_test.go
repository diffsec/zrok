package storerpc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
)

func TestEnvelopeReplyRoundTrip(t *testing.T) {
	// Encode an envelope, decode it back, verify equality.
	env := Envelope{
		Token:   "abc",
		Method:  "Findings.Create",
		Request: json.RawMessage(`{"row":{}}`),
	}
	var buf bytes.Buffer
	if err := writeEnvelope(&buf, env); err != nil {
		t.Fatalf("writeEnvelope: %v", err)
	}
	got, err := readEnvelope(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("readEnvelope: %v", err)
	}
	if got.Token != env.Token || got.Method != env.Method {
		t.Errorf("envelope mismatch: got=%+v want=%+v", got, env)
	}
	if string(got.Request) != string(env.Request) {
		t.Errorf("envelope request mismatch: got=%q want=%q", string(got.Request), string(env.Request))
	}

	// Same for Reply.
	rep := Reply{Result: json.RawMessage(`{"row":{"id":"f1"}}`)}
	var buf2 bytes.Buffer
	if err := writeReply(&buf2, rep); err != nil {
		t.Fatalf("writeReply: %v", err)
	}
	got2, err := readReply(bufio.NewReader(&buf2))
	if err != nil {
		t.Fatalf("readReply: %v", err)
	}
	if string(got2.Result) != string(rep.Result) {
		t.Errorf("reply mismatch: got=%q want=%q", string(got2.Result), string(rep.Result))
	}
}

func TestReadEnvelopeErrorOnGarbage(t *testing.T) {
	buf := bytes.NewBufferString("not-json\n")
	_, err := readEnvelope(bufio.NewReader(buf))
	if err == nil {
		t.Fatalf("expected decode error on garbage line")
	}
}
