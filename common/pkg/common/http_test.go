package common

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponseWriter_StatusAndBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &ResponseWriter{ResponseWriter: rec}

	rw.WriteHeader(201)
	if rw.StatusCode() != 201 {
		t.Fatalf("want status 201, got %d", rw.StatusCode())
	}

	n, _ := rw.Write([]byte("abc"))
	if n != 3 || rw.BytesWritten() != 3 {
		t.Fatalf("want 3 bytes written, got n=%d bytes=%d", n, rw.BytesWritten())
	}

	// Flush should delegate when supported
	rw.Flush() // httptest.ResponseRecorder implements http.Flusher
}

type fakeHijacker struct{ http.ResponseWriter }

func (fakeHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) { return nil, nil, nil }

func TestResponseWriter_HijackAndPushFallbacks(t *testing.T) {
	// Hijack supported
	rw := &ResponseWriter{ResponseWriter: fakeHijacker{httptest.NewRecorder()}}
	if _, _, err := rw.Hijack(); err != nil {
		t.Fatalf("hijack should be supported, got err: %v", err)
	}

	// Hijack not supported
	rw2 := &ResponseWriter{ResponseWriter: httptest.NewRecorder()}
	if _, _, err := rw2.Hijack(); err == nil {
		t.Fatal("expected hijack not supported error")
	}

	// Push: normally not supported on ResponseRecorder
	if err := rw2.Push("/x", nil); err == nil {
		t.Fatal("expected push not supported error")
	}
}
