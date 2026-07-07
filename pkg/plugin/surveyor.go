package plugin

import (
	"context"
	"encoding/json"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// Surveyor (one of "the Ravens") discovers an application's surface and returns a Saga
// fragment, so the descriptor can write itself. Implementations must honor ctx
// cancellation.
type Surveyor interface {
	Info() SurveyorInfo
	Survey(ctx context.Context, scope SurveyScope) (saga.Fragment, error)
}

// SurveyorInfo describes a surveyor.
type SurveyorInfo struct {
	// Name is the surveyor identifier, e.g. "k8s-images", "github-org-repos".
	Name string
	// Provides are the target kinds this surveyor can discover.
	Provides []TargetKind
	// ConfigSchema is a JSON Schema for the scope Config.
	ConfigSchema json.RawMessage
}

// SurveyScope tells a surveyor where to look, e.g. a kube context + namespace, a GitHub
// org, or an ADO project.
type SurveyScope struct {
	Kind   string
	Ref    string
	Config Config
}
