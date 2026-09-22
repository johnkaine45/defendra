package ui

const (
	reset  = "\033[0m"
	Green  = "\033[1;32m"
	Yellow = "\033[1;33m"
	Red    = "\033[1;31m"
	Dim    = "\033[2m"
	Bold   = "\033[1m"
)

func (u *IO) Paint(code, s string) string {
	if u == nil || !u.Color || s == "" {
		return s
	}
	return code + s + reset
}

func (u *IO) PaintLevel(s, level string) string {
	switch level {
	case "green":
		return u.Paint(Green, s)
	case "red":
		return u.Paint(Red, s)
	case "yellow":
		return u.Paint(Yellow, s)
	default:
		return s
	}
}

func PaintFirstLine(text, level string, color bool) string {
	if !color || text == "" {
		return text
	}
	u := &IO{Color: true}
	nl := "\n"
	i := 0
	for i < len(text) && text[i] != '\n' {
		i++
	}
	first := text[:i]
	rest := ""
	if i < len(text) {
		rest = text[i:]
		if rest == nl {
			return u.PaintLevel(first, level) + rest
		}
	}
	return u.PaintLevel(first, level) + rest
}
