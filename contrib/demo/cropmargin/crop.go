// Command cropmargin trims a rendered terminal screenshot back to its content.
//
// The tape that produces the screenshot declares a viewport taller than the report needs, on
// purpose: a height fitted to the current output fails the moment the report gains a line, and
// that failure lands during a release, after the binaries are built and signed. The cost of the
// margin is dead space at the foot of the image the README and the home page both load.
//
// Cropping afterwards removes the trade-off rather than picking a side. The viewport stays
// generous enough to absorb a report that grows; the published image is only as tall as what was
// actually drawn.
//
// The bounds come from the pixels, not from a row count. Estimating "so many lines at so many
// pixels each" is off by a few pixels either way, and the direction that clips the last line of a
// report is the one nobody notices until it is published.
package main

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
)

func main() {
	if err := cli(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "cropmargin:", err)
		os.Exit(1)
	}
}

// cli parses the arguments and runs the crop, so that everything but the exit code is testable.
func cli(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("cropmargin", flag.ContinueOnError)
	fs.SetOutput(out)
	in := fs.String("in", "", "the PNG to read")
	dst := fs.String("out", "", "where to write the cropped PNG (defaults to -in)")
	pad := fs.Int("pad", 20, "margin to leave around the content, in pixels")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dst == "" {
		*dst = *in
	}
	return run(*in, *dst, *pad, out)
}

func run(in, out string, pad int, log io.Writer) error {
	if in == "" {
		return fmt.Errorf("-in is required")
	}
	// #nosec G304 -- the image to crop is the argument of this command, which runs in a build
	// step on a path that step just wrote.
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	img, err := png.Decode(f)
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("decode %s: %w", in, err)
	}
	if closeErr != nil {
		return closeErr
	}

	cropped, err := crop(img, pad)
	if err != nil {
		return err
	}
	if cropped.Bounds() == img.Bounds() {
		_, _ = fmt.Fprintf(log, "%s: content already fills the frame, left alone\n", in)
		return nil
	}

	// #nosec G304 -- the destination is this command's own argument, and the build step that
	// calls it passes the path it just rendered.
	w, err := os.Create(out)
	if err != nil {
		return err
	}
	if err := png.Encode(w, cropped); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(log, "%s: %dx%d -> %dx%d\n", out,
		img.Bounds().Dx(), img.Bounds().Dy(),
		cropped.Bounds().Dx(), cropped.Bounds().Dy())
	return nil
}

// backgroundTolerance is how far a pixel may sit from its row's background and still count as
// background, summed across the three channels of a 16-bit color.
//
// Chosen from the image rather than by taste. On a real render the ground is not one flat value:
// it carries a step of 1/255 in places, worth 257 here, from the gradient the terminal draws and
// the palette pass that follows. Drawn text is two orders of magnitude away — the faintest row of
// glyphs measures around 150,000 against the same reference — so anything between the two
// separates them, and this sits far enough above the noise to survive another dithering pass.
//
// Comparing exactly instead finds "content" in every empty row and crops nothing, while looking
// exactly like an image that had no margin to remove.
const backgroundTolerance = 3000

// crop returns img reduced to the drawn content plus pad on every side.
//
// The background is measured per row, from the pixel at the left edge, rather than taken from one
// corner or hardcoded. Per row because the ground is a vertical gradient, so a single reference
// stops matching further down the frame; from the pixel rather than a constant because the
// terminal theme decides the color, and a hardcoded one would quietly stop cropping the day
// somebody changed the theme — which looks identical to a frame that needed no crop.
//
// That the left edge is background is guaranteed by the same tape that sets the viewport: it
// declares a padding, so the outermost column is margin. A render with content flush to the edge
// is reported rather than mis-cropped.
func crop(img image.Image, pad int) (image.Image, error) {
	b := img.Bounds()
	if b.Empty() {
		return nil, fmt.Errorf("image has no pixels")
	}

	content := image.Rectangle{Min: image.Point{X: b.Max.X, Y: b.Max.Y}, Max: b.Min}
	for y := b.Min.Y; y < b.Max.Y; y++ {
		bg := img.At(b.Min.X, y)
		for x := b.Min.X; x < b.Max.X; x++ {
			if nearlyEqual(img.At(x, y), bg) {
				continue
			}
			content.Min.X = min(content.Min.X, x)
			content.Min.Y = min(content.Min.Y, y)
			content.Max.X = max(content.Max.X, x+1)
			content.Max.Y = max(content.Max.Y, y+1)
		}
	}
	// A frame of one flat color is a render that went wrong — an empty terminal, a theme that
	// painted nothing. Cropping it to a padding-sized square would publish that as an image,
	// where the whole point of this step is that nobody looks at the file afterwards.
	if content.Empty() {
		return nil, fmt.Errorf("every pixel is the background color — the render drew nothing")
	}

	content = content.Inset(-pad).Intersect(b)
	sub, ok := img.(interface {
		SubImage(image.Rectangle) image.Image
	})
	if !ok {
		return nil, fmt.Errorf("%T cannot be cropped", img)
	}
	return sub.SubImage(content), nil
}

// nearlyEqual reports whether two colors are within backgroundTolerance of each other, summed
// across the three color channels of the 16-bit values the image package returns.
//
// The tolerance costs nothing at the edge of a glyph. Antialiasing blends toward the text color,
// which is the far end of the range from the ground, so even a tenth-strength edge pixel lands
// well above the threshold — and the body of the glyph is on the same row regardless, so a row's
// bounds do not depend on catching its faintest pixel.
func nearlyEqual(a, b color.Color) bool {
	ar, ag, ab, _ := a.RGBA()
	br, bg, bb, _ := b.RGBA()
	return diff(ar, br)+diff(ag, bg)+diff(ab, bb) <= backgroundTolerance
}

// diff is the absolute difference between two channel values.
func diff(a, b uint32) uint32 {
	if a > b {
		return a - b
	}
	return b - a
}
