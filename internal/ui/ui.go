package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type IO struct {
	In       *bufio.Reader
	Out      io.Writer
	Err      io.Writer
	Color    bool
	NoPrompt bool
}

func New(in io.Reader, out, err io.Writer) *IO {
	color := false
	if f, ok := out.(*os.File); ok {
		if isTTY(f) && os.Getenv("NO_COLOR") == "" {
			color = true
		}
	}
	return &IO{In: bufio.NewReader(in), Out: out, Err: err, Color: color}
}

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func (u *IO) Print(a ...any) { fmt.Fprint(u.Out, a...) }
func (u *IO) Printf(format string, a ...any) {
	fmt.Fprintf(u.Out, format, a...)
}
func (u *IO) Println(a ...any) { fmt.Fprintln(u.Out, a...) }

func (u *IO) ErrPrint(format string, a ...any) {
	fmt.Fprintf(u.Err, format, a...)
}

func (u *IO) Progress(step, total int, msg string) {
	fmt.Fprintf(u.Err, "Defendra • шаг %d из %d   %s\n", step, total, msg)
}

func (u *IO) Confirm(question string) (bool, error) {
	if u.NoPrompt {
		return true, nil
	}
	u.Println(question)
	u.Println("Продолжить? Нажмите Enter или напишите да / нет")
	line, err := u.In.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	s := strings.TrimSpace(strings.ToLower(line))
	s = strings.ReplaceAll(s, "ё", "е")
	// Enter = да only when the user actually pressed Enter (a newline).
	// Bare EOF / empty pipe must not confirm a destructive command.
	if err == io.EOF && s == "" {
		return false, io.EOF
	}
	switch s {
	case "", "да", "д", "yes", "y":
		return true, nil
	case "нет", "н", "no", "n":
		return false, nil
	default:
		if err == io.EOF {
			return false, io.EOF
		}
		u.Println("Напишите да или нет")
		return u.Confirm(question)
	}
}

func (u *IO) ReadLine() (string, error) {
	line, err := u.In.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), err
}
