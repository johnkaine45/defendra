package check

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

type Status string

const (
	Pass    Status = "pass"
	Fail    Status = "fail"
	Warn    Status = "warn"
	Info    Status = "info"
	Error   Status = "error"
	Skipped Status = "skipped"
)

type Finding struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Severity  Severity `json:"severity"`
	Status    Status   `json:"status"`
	Plain     string   `json:"plain"`
	Fix       string   `json:"fix"`
	Automatic bool     `json:"automatic"`
	Gates     []string `json:"gates,omitempty"`
	Evidence  any      `json:"evidence,omitempty"`
}

func f(id, title string, sev Severity, st Status, plain, fix string, auto bool, gates []string, ev any) Finding {
	return Finding{ID: id, Title: title, Severity: sev, Status: st, Plain: plain, Fix: fix, Automatic: auto, Gates: gates, Evidence: ev}
}
