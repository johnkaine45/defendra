package ui

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestConfirmEnterYes(t *testing.T) {
	u := New(strings.NewReader("\n"), io.Discard, io.Discard)
	ok, err := u.Confirm("?")
	if err != nil || !ok {
		t.Fatalf("enter: ok=%v err=%v", ok, err)
	}
}

func TestConfirmNet(t *testing.T) {
	u := New(strings.NewReader("нет\n"), io.Discard, io.Discard)
	ok, err := u.Confirm("?")
	if err != nil || ok {
		t.Fatalf("нет: ok=%v err=%v", ok, err)
	}
}

func TestConfirmEmptyEOFRefuses(t *testing.T) {
	u := New(strings.NewReader(""), io.Discard, io.Discard)
	ok, err := u.Confirm("?")
	if ok || err != io.EOF {
		t.Fatalf("empty eof: ok=%v err=%v", ok, err)
	}
}

func TestConfirmDaWithoutNewline(t *testing.T) {
	u := New(strings.NewReader("да"), io.Discard, io.Discard)
	ok, err := u.Confirm("?")
	if err != nil || !ok {
		t.Fatalf("да eof: ok=%v err=%v", ok, err)
	}
}

func TestConfirmNoPrompt(t *testing.T) {
	u := New(strings.NewReader(""), io.Discard, io.Discard)
	u.NoPrompt = true
	ok, err := u.Confirm("?")
	if err != nil || !ok {
		t.Fatalf("noprompt: ok=%v err=%v", ok, err)
	}
}

func TestConfirmStrictEnterKeeps(t *testing.T) {
	u := New(strings.NewReader("\n"), io.Discard, io.Discard)
	ok, err := u.ConfirmStrict("?")
	if err != nil || ok {
		t.Fatalf("enter: ok=%v err=%v", ok, err)
	}
}

func TestConfirmStrictDa(t *testing.T) {
	u := New(strings.NewReader("да\n"), io.Discard, io.Discard)
	ok, err := u.ConfirmStrict("?")
	if err != nil || !ok {
		t.Fatalf("да: ok=%v err=%v", ok, err)
	}
}

func TestConfirmStrictNoPromptNever(t *testing.T) {
	u := New(strings.NewReader("да\n"), io.Discard, io.Discard)
	u.NoPrompt = true
	ok, err := u.ConfirmStrict("?")
	if err != nil || ok {
		t.Fatalf("noprompt must not disable street: ok=%v err=%v", ok, err)
	}
}

func TestConfirmDangerEnterKeeps(t *testing.T) {
	u := New(strings.NewReader("\n"), io.Discard, io.Discard)
	ok, err := u.ConfirmDanger("?")
	if err != nil || ok {
		t.Fatalf("enter: ok=%v err=%v", ok, err)
	}
}

func TestConfirmDangerDa(t *testing.T) {
	var out bytes.Buffer
	u := New(strings.NewReader("да\n"), &out, io.Discard)
	ok, err := u.ConfirmDanger("Открою порт 8080")
	if err != nil || !ok {
		t.Fatalf("да: ok=%v err=%v", ok, err)
	}
	if !strings.Contains(out.String(), "Напишите да — открыть") {
		t.Fatal(out.String())
	}
}

func TestConfirmDangerNoPromptNever(t *testing.T) {
	u := New(strings.NewReader("да\n"), io.Discard, io.Discard)
	u.NoPrompt = true
	ok, err := u.ConfirmDanger("?")
	if err != nil || ok {
		t.Fatalf("noprompt must not open: ok=%v err=%v", ok, err)
	}
}

func TestConfirmWritesQuestion(t *testing.T) {
	var out bytes.Buffer
	u := New(strings.NewReader("\n"), &out, io.Discard)
	_, _ = u.Confirm("Открыть сайт")
	if !strings.Contains(out.String(), "Открыть сайт") {
		t.Fatal(out.String())
	}
}
