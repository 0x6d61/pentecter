package agent

import "time"

// DomainEvent は MainCoordinator が処理するドメインイベントの共通インターフェース。
type DomainEvent interface {
	DomainEventType() string
	Base() DomainEventBase
}

// DomainEventBase は全ドメインイベントの共通メタデータ。
type DomainEventBase struct {
	TargetID  int
	Host      string
	AgentKind AgentKind
	EmittedAt time.Time
}

// Base returns the event base metadata.
func (b DomainEventBase) Base() DomainEventBase { return b }

// NewDomainEventBase builds base metadata with current timestamp.
func NewDomainEventBase(targetID int, host string, kind AgentKind) DomainEventBase {
	return DomainEventBase{
		TargetID:  targetID,
		Host:      host,
		AgentKind: kind,
		EmittedAt: time.Now(),
	}
}

type PortDiscovered struct {
	DomainEventBase
	Port    int
	Service string
	Banner  string
	Version string
}

func (PortDiscovered) DomainEventType() string { return "port_discovered" }

type ServiceIdentified struct {
	DomainEventBase
	Port          int
	Service       string
	CVEs          []string
	AttackVectors []string
	Notes         string
}

func (ServiceIdentified) DomainEventType() string { return "service_identified" }

type PortReconInfo struct {
	Port    int
	Service string
	Banner  string
}

type ReconComplete struct {
	DomainEventBase
	Ports   []PortReconInfo
	Summary string
}

func (ReconComplete) DomainEventType() string { return "recon_complete" }

type EndpointInfo struct {
	Host   string
	Port   int
	Path   string
	Status int
}

type ParamInfo struct {
	Host      string
	Port      int
	Path      string
	Name      string
	ParamType string
}

type EndpointFound struct {
	DomainEventBase
	Port   int
	Path   string
	Status int
}

func (EndpointFound) DomainEventType() string { return "endpoint_found" }

type ParamFound struct {
	DomainEventBase
	Port      int
	Path      string
	Name      string
	ParamType string
}

func (ParamFound) DomainEventType() string { return "param_found" }

type VhostFound struct {
	DomainEventBase
	Port      int
	VhostName string
}

func (VhostFound) DomainEventType() string { return "vhost_found" }

type WebReconComplete struct {
	DomainEventBase
	Port      int
	Endpoints []EndpointInfo
	Params    []ParamInfo
	Vhosts    []string
}

func (WebReconComplete) DomainEventType() string { return "web_recon_complete" }

type VulnFound struct {
	DomainEventBase
	Port     int
	Path     string
	Param    string
	VulnType string
	Evidence string
	Severity string
}

func (VulnFound) DomainEventType() string { return "vuln_found" }

type ExploitSuccess struct {
	DomainEventBase
	Port     int
	VulnType string
	Impact   string
	Detail   string
}

func (ExploitSuccess) DomainEventType() string { return "exploit_success" }

type CredentialFound struct {
	DomainEventBase
	Port     int
	Service  string
	Username string
	Password string
}

func (CredentialFound) DomainEventType() string { return "credential_found" }

type AccessGained struct {
	DomainEventBase
	Port    int
	Service string
	Level   string
}

func (AccessGained) DomainEventType() string { return "access_gained" }

type AgentStalled struct {
	DomainEventBase
	AgentID    string
	AgentType  string
	Turn       int
	LastAction string
}

func (AgentStalled) DomainEventType() string { return "agent_stalled" }

type AgentComplete struct {
	DomainEventBase
	AgentID   string
	AgentType string
	Summary   string
}

func (AgentComplete) DomainEventType() string { return "agent_complete" }

type UserInput struct {
	DomainEventBase
	Message string
}

func (UserInput) DomainEventType() string { return "user_input" }
