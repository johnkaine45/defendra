package facts

import (
	"strconv"
	"strings"
	"time"
)

type Snapshot struct {
	CollectedAt time.Time         `json:"collected_at"`
	Host        HostFact          `json:"host"`
	SSH         SSHFact           `json:"ssh"`
	Users       []User            `json:"users"`
	Ports       []Listen          `json:"ports"`
	Firewall    Firewall          `json:"firewall"`
	Packages    Packages          `json:"packages"`
	Fail2ban    Fail2ban          `json:"fail2ban"`
	Sysctl      map[string]string `json:"sysctl"`
	Panels      []Panel           `json:"panels"`
	Perms       []FilePerm        `json:"perms"`
	Sudo        SudoFact          `json:"sudo"`
	SUID        []string          `json:"suid"`
}

type HostFact struct {
	Hostname  string `json:"hostname"`
	PrettyOS  string `json:"os"`
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Arch      string `json:"arch"`
	Desktop   bool   `json:"desktop"`
	PublicIP  string `json:"public_ip,omitempty"`
	SSHClient string `json:"ssh_client,omitempty"`
	SSHPort   int    `json:"ssh_port"`
}

type SSHFact struct {
	PermitRootLogin string   `json:"permit_root_login"`
	PasswordAuth    string   `json:"password_authentication"`
	PubkeyAuth      string   `json:"pubkey_authentication"`
	EmptyPasswords  string   `json:"permit_empty_passwords"`
	X11Forwarding   string   `json:"x11_forwarding"`
	MaxAuthTries    string   `json:"max_auth_tries"`
	AllowUsers      []string `json:"allow_users"`
	Port            int      `json:"port"`
	ConfigOK        bool     `json:"config_ok"`
	ConfigError     string   `json:"config_error,omitempty"`
}

type User struct {
	Name     string `json:"name"`
	UID      int    `json:"uid"`
	Home     string `json:"home"`
	Shell    string `json:"shell"`
	Sudo     bool   `json:"sudo"`
	HasKeys  bool   `json:"has_keys"`
	KeysMode string `json:"keys_mode,omitempty"`
}

type Listen struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Process string `json:"process"`
}

func (l Listen) Public() bool {
	a := strings.ToLower(strings.TrimSpace(l.Addr))
	if a == "" {
		return true
	}
	if a == "localhost" || a == "::1" || a == "[::1]" {
		return false
	}
	if strings.HasPrefix(a, "127.") {
		return false
	}
	if strings.HasPrefix(a, "::ffff:127.") || strings.HasPrefix(a, "[::ffff:127.") {
		return false
	}
	if strings.HasPrefix(a, "fe80:") || strings.HasPrefix(a, "[fe80:") {
		return false
	}
	return true
}

type Firewall struct {
	Installed bool     `json:"installed"`
	Active    bool     `json:"active"`
	DefaultIn string   `json:"default_incoming"`
	Allows    []string `json:"allows"`
}

func (f Firewall) AllowsPort(port int) bool {
	return f.AllowsProto(port, "tcp") || f.AllowsProto(port, "udp")
}

func (f Firewall) AllowsProto(port int, proto string) bool {
	if proto == "" {
		proto = "tcp"
	}
	want := strconv.Itoa(port)
	spec := want + "/" + proto
	for _, a := range f.Allows {
		if a == spec || a == want {
			return true
		}
	}
	return false
}

type Packages struct {
	UFW               bool `json:"ufw"`
	Fail2ban          bool `json:"fail2ban"`
	Unattended        bool `json:"unattended_upgrades"`
	UnattendedEnabled bool `json:"unattended_enabled"`
	RebootRequired    bool `json:"reboot_required"`
}

type Fail2ban struct {
	Installed bool `json:"installed"`
	Active    bool `json:"active"`
	SSHBanned int  `json:"ssh_banned"`
}

type Panel struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

type FilePerm struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Perm uint32 `json:"perm"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
}

type SudoFact struct {
	NOPASSWDAll bool `json:"nopasswd_all"`
}
