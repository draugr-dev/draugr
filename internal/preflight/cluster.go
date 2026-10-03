package preflight

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// reachCluster resolves a kubeconfig context and asks the API server behind it for its version.
//
// The context first, on its own, because a misspelled one is the likeliest failure and the one a
// reader can fix from the message: it names the contexts the kubeconfig does have. Only then the
// server, whose failure says the cluster is unreachable from here rather than undeclared.
func reachCluster(ctx context.Context, kubeCtx string) (string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	raw, err := rules.Load()
	if err != nil {
		return "", fmt.Errorf("read kubeconfig: %w", err)
	}
	resolved, err := resolveContext(raw, kubeCtx)
	if err != nil {
		return "", err
	}
	cfg, err := clientcmd.NewNonInteractiveClientConfig(*raw, resolved, &clientcmd.ConfigOverrides{}, rules).ClientConfig()
	if err != nil {
		return "", fmt.Errorf("context %s: %w", resolved, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		cfg.Timeout = time.Until(deadline)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return "", fmt.Errorf("context %s: %w", resolved, err)
	}
	v, err := client.Discovery().ServerVersion()
	if err != nil {
		return "", fmt.Errorf("context %s: the API server did not answer: %w", resolved, err)
	}
	return fmt.Sprintf("context %s · Kubernetes %s", resolved, v.GitVersion), nil
}

// resolveContext names the context a cluster is reached through: the one the descriptor names, or
// the kubeconfig's current one when it names none.
func resolveContext(raw *clientcmdapi.Config, kubeCtx string) (string, error) {
	names := slices.Sorted(maps.Keys(raw.Contexts))
	if kubeCtx == "" {
		if raw.CurrentContext == "" {
			return "", fmt.Errorf("no context is named under clusters: and the kubeconfig has no "+
				"current context (it has %s)", listOrNone(names))
		}
		kubeCtx = raw.CurrentContext
	}
	if _, ok := raw.Contexts[kubeCtx]; !ok {
		return "", fmt.Errorf("no kubeconfig context named %q (it has %s)", kubeCtx, listOrNone(names))
	}
	return kubeCtx, nil
}

func listOrNone(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	const most = 8
	if len(names) > most {
		return strings.Join(names[:most], ", ") + fmt.Sprintf(" and %d more", len(names)-most)
	}
	return strings.Join(names, ", ")
}
