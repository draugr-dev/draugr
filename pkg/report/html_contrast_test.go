package report

import (
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// aa is WCAG's contrast floor for text at normal size. The large-text allowance is not used: none
// of these tokens is reserved for large text.
const aa = 4.5

// The report's surfaces, and the tokens it draws as text on them.
var (
	surfaces   = []string{"bg", "surface", "surface-sunken"}
	textTokens = []string{"text", "muted", "faint", "accent-text", "p1", "p2", "p3", "p4", "pass"}
)

// onQuiet pairs each ink with the quiet fill it is drawn on as a chip: a priority label, the chosen
// tab, the chosen page size.
var onQuiet = map[string]string{
	"p1": "p1-quiet", "p2": "p2-quiet", "p3": "p3-quiet", "p4": "p4-quiet",
	"accent-text": "accent-quiet",
}

// onFill pairs each ink with the opaque fill it labels: a band strip, a severity chip, the chosen
// view, the verdict.
var onFill = map[string]string{
	"on-p1-fill": "p1-fill", "on-p2-fill": "p2-fill", "on-p3-fill": "p3-fill", "on-p4-fill": "p4-fill",
	"on-accent": "accent", "on-pass": "pass", "on-fail": "fail",
}

// themeBlock finds the declarations each theme applies: the bare :root, which is dark, the light
// theme a reader chose, and the light theme a light machine gets.
var themeBlock = map[string]*regexp.Regexp{
	"dark":           regexp.MustCompile(`(?s):root \{(.*?)\}`),
	"light (chosen)": regexp.MustCompile(`(?s):root\[data-theme="light"\] \{(.*?)\}`),
	"light (system)": regexp.MustCompile(`(?s):root:not\(\[data-theme="dark"\]\) \{(.*?)\}`),
}

var (
	cssComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	hexDecl    = regexp.MustCompile(`--([a-z0-9-]+):\s*#([0-9a-fA-F]{6})\s*;`)
	rgbaDecl   = regexp.MustCompile(`--([a-z0-9-]+):\s*rgb\((\d+) (\d+) (\d+) / (\d+)%\)\s*;`)
	textColor  = regexp.MustCompile(`(?:^|[^-])color:\s*var\(--([a-z0-9-]+)\)`)
)

// rgba is a token's color, with the alpha a quiet fill is drawn at; opaque tokens carry 1.
type rgba struct{ r, g, b, a float64 }

// over composites a translucent color onto an opaque one, the way the browser draws a quiet fill
// onto the surface beneath it.
func (c rgba) over(under rgba) rgba {
	mix := func(top, bottom float64) float64 { return math.Round(top*c.a + bottom*(1-c.a)) }
	return rgba{mix(c.r, under.r), mix(c.g, under.g), mix(c.b, under.b), 1}
}

func linear(v float64) float64 {
	v /= 255
	if v <= 0.04045 {
		return v / 12.92
	}
	return math.Pow((v+0.055)/1.055, 2.4)
}

func (c rgba) luminance() float64 {
	return 0.2126*linear(c.r) + 0.7152*linear(c.g) + 0.0722*linear(c.b)
}

// contrast is WCAG's contrast ratio between two opaque colors.
func contrast(a, b rgba) float64 {
	hi, lo := a.luminance(), b.luminance()
	if lo > hi {
		hi, lo = lo, hi
	}
	return (hi + 0.05) / (lo + 0.05)
}

// palettes reads the tokens in force in each theme. The light blocks restate only what changes, so
// each starts from the dark one.
func palettes(t *testing.T) map[string]map[string]rgba {
	t.Helper()
	css := cssComment.ReplaceAllString(htmlDoc, "")
	read := func(body string) map[string]rgba {
		out := map[string]rgba{}
		for _, m := range hexDecl.FindAllStringSubmatch(body, -1) {
			v, _ := strconv.ParseUint(m[2], 16, 32)
			out[m[1]] = rgba{float64(v >> 16 & 0xff), float64(v >> 8 & 0xff), float64(v & 0xff), 1}
		}
		for _, m := range rgbaDecl.FindAllStringSubmatch(body, -1) {
			n := func(s string) float64 { f, _ := strconv.ParseFloat(s, 64); return f }
			out[m[1]] = rgba{n(m[2]), n(m[3]), n(m[4]), n(m[5]) / 100}
		}
		return out
	}
	out := map[string]map[string]rgba{}
	for theme, re := range themeBlock {
		m := re.FindStringSubmatch(css)
		if m == nil {
			t.Fatalf("no %s block in the report's stylesheet", theme)
		}
		out[theme] = read(m[1])
	}
	for theme, tokens := range out {
		if theme == "dark" {
			continue
		}
		merged := maps.Clone(out["dark"])
		for k, v := range tokens {
			merged[k] = v
		}
		out[theme] = merged
	}
	return out
}

// TestEveryLabelClearsAAInEveryTheme measures every text token against every surface, each band's
// ink against its own quiet fill, and each fill's ink against the fill, in the dark theme and in
// both routes to the light one.
//
// The light theme is the one a reader prints, and a label drawn in its band's fill color reads in
// dark and vanishes on white, so a value that passes in one theme says nothing about the other.
func TestEveryLabelClearsAAInEveryTheme(t *testing.T) {
	t.Parallel()
	for theme, tokens := range palettes(t) {
		get := func(name string) rgba {
			c, ok := tokens[name]
			if !ok {
				t.Fatalf("%s: no --%s", theme, name)
			}
			return c
		}
		check := func(what string, ratio float64) {
			if ratio < aa {
				t.Errorf("%s: %s is %.2f:1, under %.1f:1", theme, what, ratio, aa)
			}
		}
		for _, ink := range textTokens {
			for _, s := range surfaces {
				check(fmt.Sprintf("--%s on --%s", ink, s), contrast(get(ink), get(s)))
				if quiet, ok := onQuiet[ink]; ok {
					check(fmt.Sprintf("--%s on --%s over --%s", ink, quiet, s), contrast(get(ink), get(quiet).over(get(s))))
				}
			}
		}
		for ink, fill := range onFill {
			check(fmt.Sprintf("--%s on --%s", ink, fill), contrast(get(ink), get(fill)))
		}
	}
}

// TestEveryTextColorIsAMeasuredToken holds each rule that colors text to a token the test above
// measures, so a label cannot be drawn in a fill or an edge color, which is measured against
// nothing.
func TestEveryTextColorIsAMeasuredToken(t *testing.T) {
	t.Parallel()
	measured := slices.Clone(textTokens)
	for ink := range onFill {
		measured = append(measured, ink)
	}
	css := cssComment.ReplaceAllString(htmlDoc, "")
	for _, m := range textColor.FindAllStringSubmatch(css, -1) {
		if !slices.Contains(measured, m[1]) {
			t.Errorf("text is colored var(--%s), which no contrast check measures; use a text "+
				"token (%s) or a fill's own ink", m[1], strings.Join(textTokens, ", "))
		}
	}
}

// deuteranomaly is Machado, Oliveira and Fernandes' simulation of deuteranomaly at full severity,
// applied in linear RGB.
var deuteranomaly = [3][3]float64{
	{0.367322, 0.860646, -0.227968},
	{0.280085, 0.672501, 0.047413},
	{-0.011820, 0.042940, 0.968881},
}

// lab is a color in CIELAB under D65, from linear RGB.
func lab(r, g, b float64) [3]float64 {
	x := (0.4124*r + 0.3576*g + 0.1805*b) / 0.95047
	y := 0.2126*r + 0.7152*g + 0.0722*b
	z := (0.0193*r + 0.1192*g + 0.9505*b) / 1.08883
	f := func(v float64) float64 {
		if v > 0.008856 {
			return math.Cbrt(v)
		}
		return 7.787*v + 16.0/116
	}
	return [3]float64{116*f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))}
}

// deutanLab is how a color looks to a reader with deuteranomaly, in CIELAB.
func deutanLab(c rgba) [3]float64 {
	in := [3]float64{linear(c.r), linear(c.g), linear(c.b)}
	var out [3]float64
	for i, row := range deuteranomaly {
		out[i] = math.Max(0, math.Min(1, row[0]*in[0]+row[1]*in[1]+row[2]*in[2]))
	}
	return lab(out[0], out[1], out[2])
}

// apart is the least CIE76 distance P1 and P2 keep for a deutan reader. The dark theme's pair sits
// near 28; a red and a gold of one lightness sit near 5, which reads as one color.
const apart = 25

// TestP1AndP2StayApartForADeutanReader holds the two highest bands to looking different with the
// most common color deficiency, in every theme, as a label and as a fill. Red and gold of one
// lightness converge for a deutan reader, so the ink that clears AA on white has to stay apart by
// more than its hue.
func TestP1AndP2StayApartForADeutanReader(t *testing.T) {
	t.Parallel()
	for theme, tokens := range palettes(t) {
		for _, pair := range [][2]string{{"p1", "p2"}, {"p1-fill", "p2-fill"}} {
			pa, oka := tokens[pair[0]]
			pb, okb := tokens[pair[1]]
			if !oka || !okb {
				t.Errorf("%s: --%s or --%s is not declared", theme, pair[0], pair[1])
				continue
			}
			a, b := deutanLab(pa), deutanLab(pb)
			d := math.Sqrt((a[0]-b[0])*(a[0]-b[0]) + (a[1]-b[1])*(a[1]-b[1]) + (a[2]-b[2])*(a[2]-b[2]))
			if d < apart {
				t.Errorf("%s: --%s and --%s are %.1f apart for a deutan reader, under %d",
					theme, pair[0], pair[1], d, apart)
			}
		}
	}
}
