package sarif

import "testing"

func TestAFrameNamesItsPackageAndReceiver(t *testing.T) {
	for _, tc := range []struct {
		frame CallFrame
		want  string
	}{
		{CallFrame{Function: "Writer.Close", Package: "compress/gzip"}, "gzip.Writer.Close"},
		{CallFrame{Function: "conn.Close", Package: "net/http"}, "http.conn.Close"},
		{CallFrame{Function: "Encode", Package: "github.com/klauspost/compress/zstd"}, "zstd.Encode"},
		{CallFrame{Function: "Load", Package: "github.com/acme/cfg/v2"}, "cfg.Load"},
		{CallFrame{Function: "main"}, "main"},
	} {
		if got := tc.frame.Symbol(); got != tc.want {
			t.Errorf("Symbol(%+v) = %q, want %q", tc.frame, got, tc.want)
		}
	}
}

func TestTwoMethodsOfOneNameReadAsTwoCalls(t *testing.T) {
	p := CallPath{Frames: []CallFrame{
		{Function: "Writer.Close", Package: "compress/gzip"},
		{Function: "Writer.Close", Package: "bufio"},
	}}
	if got, want := p.String(), "gzip.Writer.Close → bufio.Writer.Close"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

func TestTheShortestPathIsTheSameInAnyOrder(t *testing.T) {
	long := CallPath{Frames: []CallFrame{{Function: "main"}, {Function: "a"}, {Function: "b"}}}
	flush := CallPath{Frames: []CallFrame{
		{Function: "response.FlushError", Package: "net/http"},
		{Function: "Writer.Flush", Package: "bufio"},
	}}
	hijack := CallPath{Frames: []CallFrame{
		{Function: "response.Hijack", Package: "net/http"},
		{Function: "conn.hijackLocked", Package: "net/http"},
	}}
	want := flush.String()
	for _, paths := range [][]CallPath{
		{long, flush, hijack},
		{long, hijack, flush},
		{hijack, flush, long},
		{flush, long, hijack},
	} {
		got, ok := ShortestCallPath(paths)
		if !ok || got.String() != want {
			t.Errorf("ShortestCallPath(%v) = %q, %v; want %q", paths, got.String(), ok, want)
		}
	}
}

func TestNoPathIsReportedAsNone(t *testing.T) {
	for _, paths := range [][]CallPath{nil, {{}}} {
		if got, ok := ShortestCallPath(paths); ok {
			t.Errorf("ShortestCallPath(%v) = %q, want none", paths, got.String())
		}
	}
}
