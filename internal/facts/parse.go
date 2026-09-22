package facts

import (
	"bufio"
	"strconv"
	"strings"
)

func ParseSSHDT(out string) SSHFact {
	f := SSHFact{Port: 22, ConfigOK: true}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.Replace(line, "=", " ", 1)
		k, v, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "permitrootlogin":
			f.PermitRootLogin = v
		case "passwordauthentication":
			f.PasswordAuth = v
		case "pubkeyauthentication":
			f.PubkeyAuth = v
		case "permitemptypasswords":
			f.EmptyPasswords = v
		case "x11forwarding":
			f.X11Forwarding = v
		case "maxauthtries":
			f.MaxAuthTries = v
		case "port":
			if n, err := strconv.Atoi(v); err == nil {
				f.Port = n
			}
		case "allowusers":
			f.AllowUsers = strings.Fields(v)
		}
	}
	return f
}

func ParseSS(out string) []Listen {
	var res []Listen
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		up := strings.ToUpper(line)
		low := strings.ToLower(line)
		udp := strings.Contains(low, "udp")
		listen := strings.Contains(up, "LISTEN")
		unconn := strings.Contains(up, "UNCONN")
		if unconn && !udp {
			continue
		}
		if !listen && !unconn {
			continue
		}
		fields := strings.Fields(line)
		local := pickLocal(fields)
		if local == "" {
			continue
		}
		addr, portStr := splitHostPort(local)
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		l := Listen{Proto: "tcp", Addr: addr, Port: port}
		if udp {
			l.Proto = "udp"
		}
		if unconn && !l.Public() {
			continue
		}
		if i := strings.Index(line, `users:(("`); i >= 0 {
			rest := line[i+len(`users:(("`):]
			if j := strings.Index(rest, `"`); j > 0 {
				l.Process = rest[:j]
			}
		}
		res = append(res, l)
	}
	return res
}

func pickLocal(fields []string) string {
	for _, f := range fields {
		if !strings.Contains(f, ":") || strings.HasPrefix(f, "users:") {
			continue
		}
		_, port := splitHostPort(f)
		if _, err := strconv.Atoi(port); err == nil {
			return f
		}
	}
	return ""
}

func splitHostPort(local string) (string, string) {
	if strings.HasPrefix(local, "[") {
		end := strings.Index(local, "]:")
		if end > 0 {
			return local[1:end], local[end+2:]
		}
	}
	i := strings.LastIndex(local, ":")
	if i < 0 {
		return local, ""
	}
	addr := local[:i]
	if addr == "*" {
		addr = "0.0.0.0"
	}
	return addr, local[i+1:]
}

func ParseUFW(out string) Firewall {
	fw := Firewall{}
	low := strings.ToLower(out)
	if strings.Contains(low, "status: active") {
		fw.Installed = true
		fw.Active = true
	} else if strings.Contains(low, "status: inactive") {
		fw.Installed = true
		fw.Active = false
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		ll := strings.ToLower(line)
		if strings.Contains(ll, "default: deny (incoming)") {
			fw.DefaultIn = "deny"
		}
		if strings.Contains(ll, "default: allow (incoming)") {
			fw.DefaultIn = "allow"
		}
		// "22/tcp                     ALLOW       Anywhere"
		if strings.Contains(ll, "allow") && !strings.Contains(ll, "default") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				tok := fields[0]
				if n, rest, ok := strings.Cut(tok, "/"); ok {
					if _, err := strconv.Atoi(n); err == nil && (rest == "tcp" || rest == "udp") {
						fw.Allows = appendUnique(fw.Allows, n+"/"+rest)
					}
				} else if _, err := strconv.Atoi(tok); err == nil {
					fw.Allows = appendUnique(fw.Allows, tok+"/tcp")
				}
				if strings.Contains(ll, "openssh") {
					fw.Allows = appendUnique(fw.Allows, "22/tcp")
				}
			}
		}
	}
	return fw
}

func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

func ParseFail2banSSH(out string) int {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "Currently banned") {
			fields := strings.Fields(line)
			if n, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
				return n
			}
		}
	}
	return 0
}
