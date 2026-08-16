package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// frame draws a background-filled image with one lit pixel at each of the given points.
func frame(w, h int, bg color.RGBA, lit ...image.Point) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.SetRGBA(x, y, bg)
		}
	}
	for _, p := range lit {
		img.SetRGBA(p.X, p.Y, color.RGBA{R: 0xF8, G: 0xF8, B: 0xF2, A: 0xFF})
	}
	return img
}

var dracula = color.RGBA{R: 0x28, G: 0x2A, B: 0x36, A: 0xFF}

// TestCropKeepsThePaddingAndDropsTheRest is the whole point: the viewport is deliberately taller
// than the report, and what gets published should be as tall as what was drawn.
func TestCropKeepsThePaddingAndDropsTheRest(t *testing.T) {
	// Content between y=40 and y=60, in a frame 400 tall — most of it empty.
	img := frame(200, 400, dracula, image.Pt(30, 40), image.Pt(120, 60))

	got, err := crop(img, 20)
	if err != nil {
		t.Fatal(err)
	}
	want := image.Rect(10, 20, 141, 81) // content bounds, inset by the padding
	if got.Bounds() != want {
		t.Errorf("cropped to %v, want %v", got.Bounds(), want)
	}
}

// TestCropNeverClipsTheContent guards the direction that matters. An image with dead space is
// untidy; one missing the last line of the report is wrong, and looks fine in the file listing.
func TestCropNeverClipsTheContent(t *testing.T) {
	last := image.Pt(150, 300)
	img := frame(400, 500, dracula, image.Pt(10, 10), last)

	got, err := crop(img, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !last.In(got.Bounds()) {
		t.Errorf("the last drawn pixel %v fell outside the crop %v", last, got.Bounds())
	}
}

// TestCropStopsAtTheFrame: padding around content that already sits at the edge cannot invent
// pixels, and a rectangle outside the source would panic on encode.
func TestCropStopsAtTheFrame(t *testing.T) {
	img := frame(100, 100, dracula, image.Pt(0, 0), image.Pt(99, 99))

	got, err := crop(img, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Bounds().In(img.Bounds()) {
		t.Errorf("crop %v escaped the source %v", got.Bounds(), img.Bounds())
	}
}

// TestCropReadsTheBackgroundRatherThanAssumingIt: a hardcoded colour would stop cropping the day
// the theme changed, and that looks identical to the tape being correctly sized.
func TestCropReadsTheBackgroundRatherThanAssumingIt(t *testing.T) {
	pale := color.RGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	img := frame(200, 400, pale, image.Pt(50, 50))

	got, err := crop(img, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got.Bounds().Dy() > 30 {
		t.Errorf("a light theme was not cropped: %v", got.Bounds())
	}
}

// TestCropRefusesAnEmptyRender. Cropping a blank frame to a padding-sized square would publish
// the failure as an image, and this step exists precisely because nobody opens the file after.
func TestCropRefusesAnEmptyRender(t *testing.T) {
	if _, err := crop(frame(100, 100, dracula), 20); err == nil {
		t.Fatal("a frame with nothing drawn on it should be an error")
	}
}

// TestRunLeavesAFullFrameAlone: rewriting an image that needs no crop would churn the committed
// PNG on every render and open a pull request saying nothing changed.
func TestRunLeavesAFullFrameAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "full.png")
	writePNG(t, path, frame(50, 50, dracula, image.Pt(0, 0), image.Pt(49, 49)))

	before, err := os.ReadFile(path) // #nosec G304 -- a path built under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := run(path, path, 20, io.Discard); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- a path built under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("an image that needed no crop was rewritten anyway")
	}
}

// TestRunWritesTheCroppedImage covers the round trip through the files, not only the geometry.
func TestRunWritesTheCroppedImage(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "tall.png")
	out := filepath.Join(dir, "short.png")
	writePNG(t, in, frame(200, 400, dracula, image.Pt(100, 50)))

	if err := run(in, out, 10, io.Discard); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(out) // #nosec G304 -- a path built under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	img, err := png.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dy() >= 400 {
		t.Errorf("the written image was not cropped: %v", img.Bounds())
	}
}

// TestRunNeedsAnInput keeps a missing flag from silently doing nothing.
func TestRunNeedsAnInput(t *testing.T) {
	err := run("", "", 20, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "-in") {
		t.Errorf("want an error naming the missing flag, got: %v", err)
	}
}

// TestRunReportsAnUnreadableFile rather than treating it as nothing to crop.
func TestRunReportsAnUnreadableFile(t *testing.T) {
	if err := run(filepath.Join(t.TempDir(), "absent.png"), "", 20, io.Discard); err == nil {
		t.Fatal("a missing input should be an error")
	}
	dir := t.TempDir()
	notPNG := filepath.Join(dir, "x.png")
	if err := os.WriteFile(notPNG, []byte("not a png"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(notPNG, "", 20, io.Discard); err == nil {
		t.Fatal("a file that is not a PNG should be an error")
	}
}

func writePNG(t *testing.T, path string, img image.Image) {
	t.Helper()
	f, err := os.Create(path) // #nosec G304 -- a path this test just built under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestRunReportsAnUnwritableDestination: the crop is a build step nobody watches, so a
// destination it cannot write has to fail the step rather than leave the previous image in place
// and report success.
func TestRunReportsAnUnwritableDestination(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "tall.png")
	writePNG(t, in, frame(200, 400, dracula, image.Pt(100, 50)))

	err := run(in, filepath.Join(dir, "no-such-dir", "out.png"), 10, io.Discard)
	if err == nil {
		t.Fatal("a destination that cannot be created should be an error")
	}
}

// TestCliCropsThroughTheFlags covers the argument handling, including -out defaulting to -in.
func TestCliCropsThroughTheFlags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tall.png")
	writePNG(t, path, frame(200, 400, dracula, image.Pt(100, 50)))

	var log bytes.Buffer
	if err := cli([]string{"-in", path, "-pad", "10"}, &log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "200x400 ->") {
		t.Errorf("the step should say what it did, got: %s", log.String())
	}

	f, err := os.Open(path) // #nosec G304 -- a path built under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	img, err := png.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dy() >= 400 {
		t.Errorf("-out defaulting to -in did not rewrite the file: %v", img.Bounds())
	}
}

// TestCliRejectsAnUnknownFlag rather than cropping with a default nobody asked for.
func TestCliRejectsAnUnknownFlag(t *testing.T) {
	if err := cli([]string{"-nope"}, io.Discard); err == nil {
		t.Fatal("an unknown flag should be an error")
	}
}

// opaque is an image that cannot produce a sub-image.
type opaque struct{ image.Image }

// TestCropRefusesAnImageItCannotSlice: returning the original unchanged would look exactly like
// an image that needed no crop, and the dead space would ship.
func TestCropRefusesAnImageItCannotSlice(t *testing.T) {
	img := opaque{frame(100, 200, dracula, image.Pt(50, 50))}
	if _, err := crop(img, 10); err == nil {
		t.Fatal("an image with no SubImage method should be an error, not a silent pass-through")
	}
}

// TestCropRefusesAnImageWithNoPixels: reading the background from the first pixel needs there to
// be one, and a zero-sized render is a failure upstream worth naming here.
func TestCropRefusesAnImageWithNoPixels(t *testing.T) {
	if _, err := crop(image.NewRGBA(image.Rect(0, 0, 0, 0)), 10); err == nil {
		t.Fatal("an image with no pixels should be an error")
	}
}
