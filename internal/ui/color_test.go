package ui

import "testing"

func TestPaintOff(t *testing.T) {
	u := &IO{Color: false}
	if u.Paint(Green, "x") != "x" {
		t.Fatal(u.Paint(Green, "x"))
	}
}

func TestPaintOn(t *testing.T) {
	u := &IO{Color: true}
	got := u.Paint(Green, "x")
	if got == "x" || got[:1] != "\033" {
		t.Fatalf("%q", got)
	}
}

func TestPaintFirstLine(t *testing.T) {
	in := "Defendra • порядок\n\n  Вход\n"
	plain := PaintFirstLine(in, "green", false)
	if plain != in {
		t.Fatal(plain)
	}
	color := PaintFirstLine(in, "green", true)
	if color == in || color[:1] != "\033" {
		t.Fatalf("%q", color)
	}
	if color[len(color)-6:] != "  Вход\n" && !containsTail(color, "  Вход\n") {
		t.Fatalf("body lost: %q", color)
	}
}

func containsTail(s, tail string) bool {
	return len(s) >= len(tail) && s[len(s)-len(tail):] == tail
}
