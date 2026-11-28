package tui

import (
	"bytes"
	"math"
	"strconv"
	"strings"
	"testing"
)

// The roles a reader tells apart by color, by the sixteen-color code exact is keyed by. The P4
// chip's grey and the muted text's grey are one role drawn twice, so only one of them is here.
var distinctRoles = []struct {
	name  string
	style Style
}{
	{"red (FAIL, P1, critical)", StyleHigh},
	{"fix (pass, fixed version)", StylePass},
	{"medium (P2, caveats)", StyleMedium},
	{"info (P3)", StyleInfo},
	{"muted (P4, supporting text)", StyleMuted},
}

// minDistance is the least CIEDE2000 distance two roles keep under normal vision, deuteranomaly and
// protanomaly. Every pair in both palettes clears it, the closest by 1.1, and the green fix color
// both replaced sat 4.3 from red under deuteranomaly, which is the failure this holds off.
const minDistance = 10.0

// Machado, Oliveira and Fernandes (2009), severity 1.0, applied in linear RGB.
var visions = map[string][3][3]float64{
	"normal":        {{1, 0, 0}, {0, 1, 0}, {0, 0, 1}},
	"deuteranomaly": {{0.367322, 0.860646, -0.227968}, {0.280085, 0.672501, 0.047413}, {-0.011820, 0.042940, 0.968881}},
	"protanomaly":   {{0.152286, 1.052583, -0.204868}, {0.114503, 0.786281, 0.099216}, {-0.003882, -0.048116, 1.051998}},
}

// A pass or a fixed version drawn in a color that a red-green deficient reader sees as the
// failure's red argues with the word beside it. Every pair of roles stays apart, as the most
// common two deficiencies see them, in every palette, so a later change of color cannot merge two
// of them again.
func TestTheRolesStayApart(t *testing.T) {
	for _, pal := range Palettes() {
		for i, a := range distinctRoles {
			for _, b := range distinctRoles[i+1:] {
				ca, cb := roleRGB(t, pal, a.style), roleRGB(t, pal, b.style)
				for vision, m := range visions {
					if d := ciede2000(lab(simulate(ca, m)), lab(simulate(cb, m))); d < minDistance {
						t.Errorf("%s: %s and %s are %.1f apart under %s vision, want at least %.0f",
							pal, a.name, b.name, d, vision, minDistance)
					}
				}
			}
		}
	}
}

// The light-background palette is for a reader whose terminal is white, so every color in it keeps
// 3:1 there, the floor WCAG sets for large and bold text, and stays readable on a dark one.
func TestTheLightBackgroundPaletteReadsOnWhite(t *testing.T) {
	white, dark := [3]float64{255, 255, 255}, [3]float64{23, 23, 23}
	for _, r := range distinctRoles {
		c := roleRGB(t, PaletteLightBackground, r.style)
		if got := contrast(c, white); got < 3 {
			t.Errorf("%s on white = %.2f:1, want at least 3:1", r.name, got)
		}
		if got := contrast(c, dark); got < 4.5 {
			t.Errorf("%s on #171717 = %.2f:1, want at least 4.5:1", r.name, got)
		}
	}
	// What the palette exists for: the standard medium is all but gone on white.
	if got := contrast(roleRGB(t, PaletteStandard, StyleMedium), white); got >= 3 {
		t.Errorf("standard medium on white = %.2f:1; if it reads there now, the light palette needs a new reason", got)
	}
}

// Both palettes color every role the same way, so a role one of them forgot falls back to the
// sixteen-color code in that palette alone.
func TestEveryPaletteColorsTheSameRoles(t *testing.T) {
	std := palettes[PaletteStandard]
	for _, pal := range Palettes() {
		c := palettes[pal]
		if len(c.exact) != len(std.exact) || len(c.chips) != len(std.chips) {
			t.Errorf("%s colors %d roles and fills %d, want %d and %d", pal, len(c.exact), len(c.chips), len(std.exact), len(std.chips))
		}
		for style := range std.exact {
			if _, ok := c.exact[style]; !ok {
				t.Errorf("%s has no color for %q", pal, style)
			}
		}
		for style := range std.chips {
			if _, ok := c.chips[style]; !ok {
				t.Errorf("%s has no fill for %q", pal, style)
			}
		}
	}
}

// The setting reaches every painter For makes after it, a misspelled one is refused with the
// names that exist, and a painter whose palette is unknown draws the standard one rather than
// nothing.
func TestSetPaletteChoosesWhatForDrawsIn(t *testing.T) {
	t.Cleanup(func() { _ = SetPalette(PaletteStandard) })
	t.Setenv("COLORTERM", "truecolor")
	if err := SetPalette(""); err != nil || ActivePalette() != PaletteStandard {
		t.Fatalf("SetPalette(\"\") = %v, active %q, want the standard palette", err, ActivePalette())
	}
	if err := SetPalette(PaletteLightBackground); err != nil {
		t.Fatal(err)
	}
	p := For(&bytes.Buffer{})
	if p.palette != PaletteLightBackground {
		t.Errorf("For drew in %q, want %q", p.palette, PaletteLightBackground)
	}
	full := p.In(PaletteLightBackground)
	full.color, full.full = true, true
	if got := full.Paint(StyleMedium, "x"); !strings.Contains(got, "38;2;214;121;0") {
		t.Errorf("light-background medium = %q", got)
	}
	if got := full.Chip(StyleFail, "FAIL"); !strings.Contains(got, "48;2;224;82;94") {
		t.Errorf("light-background FAIL chip = %q", got)
	}
	err := SetPalette("high-contrast")
	if err == nil || !strings.Contains(err.Error(), "standard, light-background") {
		t.Errorf("SetPalette(high-contrast) = %v, want the names that exist", err)
	}
	if ActivePalette() != PaletteLightBackground {
		t.Errorf("a refused name changed the palette to %q", ActivePalette())
	}
	if got := FullColorPainter().In("nonsense").Paint(StylePass, "x"); !strings.Contains(got, "38;2;53;137;233") {
		t.Errorf("unknown palette painted %q, want the standard fix color", got)
	}
}

// roleRGB is the color a palette draws a role in, read back out of its escape code.
func roleRGB(t *testing.T, pal Palette, style Style) [3]float64 {
	t.Helper()
	code := string(palettes[pal].exact[style])
	_, rgb, ok := strings.Cut(code, "38;2;")
	if !ok {
		t.Fatalf("%s %q is not a twenty-four-bit color: %q", pal, style, code)
	}
	parts := strings.Split(rgb, ";")
	var c [3]float64
	for k := range c {
		n, err := strconv.Atoi(parts[k])
		if err != nil {
			t.Fatalf("%s %q: %v", pal, style, err)
		}
		c[k] = float64(n)
	}
	return c
}

func linear(v float64) float64 {
	v /= 255
	if v <= 0.04045 {
		return v / 12.92
	}
	return math.Pow((v+0.055)/1.055, 2.4)
}

func simulate(c [3]float64, m [3][3]float64) [3]float64 {
	l := [3]float64{linear(c[0]), linear(c[1]), linear(c[2])}
	var out [3]float64
	for i := range out {
		out[i] = math.Min(1, math.Max(0, m[i][0]*l[0]+m[i][1]*l[1]+m[i][2]*l[2]))
	}
	return out
}

func luminance(l [3]float64) float64 { return 0.2126*l[0] + 0.7152*l[1] + 0.0722*l[2] }

// contrast is the WCAG contrast ratio between two sRGB colors.
func contrast(a, b [3]float64) float64 {
	x := luminance([3]float64{linear(a[0]), linear(a[1]), linear(a[2])})
	y := luminance([3]float64{linear(b[0]), linear(b[1]), linear(b[2])})
	if x < y {
		x, y = y, x
	}
	return (x + 0.05) / (y + 0.05)
}

// lab is CIE L*a*b* under D65 of a color in linear RGB.
func lab(l [3]float64) [3]float64 {
	x := 0.4124564*l[0] + 0.3575761*l[1] + 0.1804375*l[2]
	y := 0.2126729*l[0] + 0.7151522*l[1] + 0.0721750*l[2]
	z := 0.0193339*l[0] + 0.1191920*l[1] + 0.9503041*l[2]
	f := func(t float64) float64 {
		if t > 216.0/24389 {
			return math.Cbrt(t)
		}
		return (24389.0/27*t + 16) / 116
	}
	fx, fy, fz := f(x/0.95047), f(y), f(z/1.08883)
	return [3]float64{116*fy - 16, 500 * (fx - fy), 200 * (fy - fz)}
}

func sq(x float64) float64 { return x * x }

// ciede2000 is the CIEDE2000 color difference (Sharma, Wu and Dalal 2005).
func ciede2000(p, q [3]float64) float64 {
	rad := func(d float64) float64 { return d * math.Pi / 180 }
	deg := func(r float64) float64 { return r * 180 / math.Pi }
	l1, a1, b1 := p[0], p[1], p[2]
	l2, a2, b2 := q[0], q[1], q[2]
	cb := (math.Hypot(a1, b1) + math.Hypot(a2, b2)) / 2
	g := 0.5 * (1 - math.Sqrt(math.Pow(cb, 7)/(math.Pow(cb, 7)+math.Pow(25, 7))))
	a1p, a2p := (1+g)*a1, (1+g)*a2
	c1p, c2p := math.Hypot(a1p, b1), math.Hypot(a2p, b2)
	h1p := math.Mod(deg(math.Atan2(b1, a1p))+360, 360)
	h2p := math.Mod(deg(math.Atan2(b2, a2p))+360, 360)
	dl, dc := l2-l1, c2p-c1p
	dh := h2p - h1p
	switch {
	case c1p*c2p == 0:
		dh = 0
	case dh > 180:
		dh -= 360
	case dh < -180:
		dh += 360
	}
	dH := 2 * math.Sqrt(c1p*c2p) * math.Sin(rad(dh/2))
	lbp, cbp := (l1+l2)/2, (c1p+c2p)/2
	var hbp float64
	switch {
	case c1p*c2p == 0:
		hbp = h1p + h2p
	case math.Abs(h1p-h2p) <= 180:
		hbp = (h1p + h2p) / 2
	case h1p+h2p < 360:
		hbp = (h1p + h2p + 360) / 2
	default:
		hbp = (h1p + h2p - 360) / 2
	}
	tt := 1 - 0.17*math.Cos(rad(hbp-30)) + 0.24*math.Cos(rad(2*hbp)) + 0.32*math.Cos(rad(3*hbp+6)) - 0.20*math.Cos(rad(4*hbp-63))
	dth := 30 * math.Exp(-sq((hbp-275)/25))
	rc := 2 * math.Sqrt(math.Pow(cbp, 7)/(math.Pow(cbp, 7)+math.Pow(25, 7)))
	sl := 1 + 0.015*sq(lbp-50)/math.Sqrt(20+sq(lbp-50))
	sc := 1 + 0.045*cbp
	sh := 1 + 0.015*cbp*tt
	rt := -math.Sin(rad(2*dth)) * rc
	return math.Sqrt(sq(dl/sl) + sq(dc/sc) + sq(dH/sh) + rt*(dc/sc)*(dH/sh))
}

// The arithmetic is checked against Sharma, Wu and Dalal's own test pairs, so a distance the test
// above reports is CIEDE2000 and not something near it.
func TestCIEDE2000MatchesItsPublishedTestData(t *testing.T) {
	for _, tc := range []struct {
		p, q [3]float64
		want float64
	}{
		{[3]float64{50, 2.6772, -79.7751}, [3]float64{50, 0, -82.7485}, 2.0425},
		{[3]float64{50, -1, 2}, [3]float64{50, 0, 0}, 2.3669},
		{[3]float64{2.0776, 0.0795, -1.1350}, [3]float64{0.9033, -0.0636, -0.5514}, 0.9082},
		{[3]float64{22.7233, 20.0904, -46.6940}, [3]float64{23.0331, 14.9730, -42.5619}, 2.0373},
	} {
		if got := ciede2000(tc.p, tc.q); math.Abs(got-tc.want) > 0.0001 {
			t.Errorf("ΔE00(%v, %v) = %.4f, want %.4f", tc.p, tc.q, got, tc.want)
		}
	}
}
