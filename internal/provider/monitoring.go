package provider

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	opensearchv1 "github.com/opensearch-project/opensearch-k8s-operator/opensearch-operator/api/opensearch.org/v1"

	corev1alpha1 "github.com/openeverest/openeverest/v2/api/core/v1alpha1"
	"github.com/openeverest/openeverest/v2/provider-runtime/controller"
)

const (
	// monitoringRoleName is the OpenSearch security role scoped to metrics:
	// cluster-level and index-level monitor actions only, the permission set
	// the opensearch-prometheus-exporter plugin's own docs call for.
	monitoringRoleName = "opensearch-monitoring"
	// monitoringUsername is the dedicated low-privilege user the
	// ServiceMonitor the operator creates scrapes metrics with, instead of
	// the admin user.
	monitoringUsername = "monitoring"
)

// monitoringSecretName is the Secret holding the dedicated monitoring user's
// credentials (keys "username"/"password"), referenced by
// general.monitoring.monitoringUserSecret.
func monitoringSecretName(clusterName string) string {
	return clusterName + "-monitoring-password"
}

// monitoringParameters are the monitoring component's own settings, beyond
// what the base Instance spec component covers.
type monitoringParameters struct {
	// ScrapeInterval is the Prometheus scrape interval, e.g. "30s". Left
	// empty, the operator defaults to 30s.
	ScrapeInterval string `json:"scrapeInterval,omitempty"`
	// PluginURL overrides where the operator downloads the
	// opensearch-prometheus-exporter plugin from, for air-gapped clusters
	// that cannot reach GitHub releases.
	PluginURL string `json:"pluginUrl,omitempty"`
}

func monitoringParametersFromComponent(component corev1alpha1.ComponentSpec) (monitoringParameters, error) {
	var p monitoringParameters
	if component.Parameters == nil || len(component.Parameters.Raw) == 0 {
		return p, nil
	}
	if err := json.Unmarshal(component.Parameters.Raw, &p); err != nil {
		return p, fmt.Errorf("decode monitoring component parameters: %w", err)
	}
	return p, nil
}

// buildMonitoringConfig maps the optional monitoring component onto the
// OpenSearchCluster's embedded general.monitoring block. The operator
// installs the opensearch-prometheus-exporter plugin matching the cluster's
// own version and creates a prometheus-operator ServiceMonitor for it
// (tolerating a missing ServiceMonitor CRD); this provider only supplies the
// dedicated scrape credentials and the optional overrides.
func buildMonitoringConfig(c *controller.Context, component corev1alpha1.ComponentSpec) (opensearchv1.MonitoringConfig, error) {
	params, err := monitoringParametersFromComponent(component)
	if err != nil {
		return opensearchv1.MonitoringConfig{}, err
	}
	return opensearchv1.MonitoringConfig{
		Enable:               true,
		MonitoringUserSecret: monitoringSecretName(c.Name()),
		ScrapeInterval:       params.ScrapeInterval,
		PluginURL:            params.PluginURL,
	}, nil
}

// syncMonitoringUser creates, or rotates into, the dedicated low-privilege
// OpenSearch user the ServiceMonitor scrapes metrics with: a role limited to
// the cluster_monitor and indices_monitor action groups, and an internal
// user mapped to it. Requires the cluster's admin credentials and CA to
// already exist; if they don't yet (cluster still bootstrapping), this is a
// no-op and syncing catches up on a later reconcile, matching
// mirrorScheduledBackups.
func syncMonitoringUser(c *controller.Context) error {
	osClient, err := newOpenSearchClientFunc(c)
	if err != nil {
		return nil
	}

	password, err := ensureMonitoringSecret(c)
	if err != nil {
		return err
	}

	if err := osClient.do(http.MethodPut, "/_plugins/_security/api/roles/"+monitoringRoleName, map[string]any{
		"cluster_permissions": []string{"cluster_monitor"},
		"index_permissions": []map[string]any{{
			"index_patterns":  []string{"*"},
			"allowed_actions": []string{"indices_monitor"},
		}},
	}, nil); err != nil {
		return fmt.Errorf("create monitoring role: %w", err)
	}

	if err := osClient.do(http.MethodPut, "/_plugins/_security/api/internalusers/"+monitoringUsername, map[string]any{
		"password": password,
	}, nil); err != nil {
		return fmt.Errorf("create monitoring user: %w", err)
	}

	if err := osClient.do(http.MethodPut, "/_plugins/_security/api/rolesmapping/"+monitoringRoleName, map[string]any{
		"users": []string{monitoringUsername},
	}, nil); err != nil {
		return fmt.Errorf("map monitoring role: %w", err)
	}

	return nil
}

// ensureMonitoringSecret returns the monitoring user's password, generating
// and storing one on first sync and reusing it on every later one so the
// internal user's password and the Secret the ServiceMonitor reads never
// drift apart.
func ensureMonitoringSecret(c *controller.Context) (string, error) {
	name := monitoringSecretName(c.Name())
	existing := &corev1.Secret{}
	if err := c.Get(existing, name); err == nil {
		return string(existing.Data["password"]), nil
	} else if !apierrors.IsNotFound(err) {
		return "", fmt.Errorf("get monitoring credentials secret: %w", err)
	}

	password, err := generatePassword()
	if err != nil {
		return "", err
	}
	secret := &corev1.Secret{
		ObjectMeta: c.ObjectMeta(name),
		Data: map[string][]byte{
			"username": []byte(monitoringUsername),
			"password": []byte(password),
		},
	}
	if err := c.Apply(secret); err != nil {
		return "", fmt.Errorf("create monitoring credentials secret: %w", err)
	}
	return password, nil
}

func generatePassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate monitoring password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
