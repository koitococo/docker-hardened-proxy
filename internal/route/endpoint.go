package route

// EndpointKind classifies Docker API endpoints for audit routing.
type EndpointKind int

const (
	// Passthrough endpoints are forwarded without auditing.
	Passthrough EndpointKind = iota
	// ContainerCreate is POST /containers/create.
	ContainerCreate
	// ContainerOp is an operation on a specific container (inspect, start, stop, restart, kill, rm, etc).
	ContainerOp
	// ContainerList is GET /containers/json.
	ContainerList
	// ExecCreate is POST /containers/{id}/exec.
	ExecCreate
	// ExecOp is an operation on an exec instance (start, resize, inspect, json).
	ExecOp
	// Build is POST /build.
	Build
	// Denied endpoints are blocked by default (unrecognized/dangerous paths).
	Denied
)

func (k EndpointKind) String() string {
	switch k {
	case ContainerCreate:
		return "container_create"
	case ContainerOp:
		return "container_op"
	case ContainerList:
		return "container_list"
	case ExecCreate:
		return "exec_create"
	case ExecOp:
		return "exec_op"
	case Build:
		return "build"
	case Denied:
		return "denied"
	default:
		return "passthrough"
	}
}
