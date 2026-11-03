package provider

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1alpha1 "github.com/openeverest/openeverest/v2/api/core/v1alpha1"
)

func TestMonitoringParametersFromComponent(t *testing.T) {
	t.Run("no parameters", func(t *testing.T) {
		p, err := monitoringParametersFromComponent(corev1alpha1.ComponentSpec{})

		require.NoError(t, err)
		assert.Equal(t, monitoringParameters{}, p)
	})

	t.Run("decodes scrapeInterval and pluginUrl", func(t *testing.T) {
		raw, err := json.Marshal(map[string]any{"scrapeInterval": "15s", "pluginUrl": "https://example.test/plugin.zip"})
		require.NoError(t, err)
		component := corev1alpha1.ComponentSpec{Parameters: &runtime.RawExtension{Raw: raw}}

		p, err := monitoringParametersFromComponent(component)

		require.NoError(t, err)
		assert.Equal(t, "15s", p.ScrapeInterval)
		assert.Equal(t, "https://example.test/plugin.zip", p.PluginURL)
	})

	t.Run("invalid JSON is rejected", func(t *testing.T) {
		component := corev1alpha1.ComponentSpec{Parameters: &runtime.RawExtension{Raw: []byte("not json")}}

		_, err := monitoringParametersFromComponent(component)

		assert.ErrorContains(t, err, "decode monitoring component parameters")
	})
}

func TestBuildMonitoringConfig(t *testing.T) {
	c, _ := newTestContext(t, testInstance(validEngine()))

	cfg, err := buildMonitoringConfig(c, corev1alpha1.ComponentSpec{})

	require.NoError(t, err)
	assert.True(t, cfg.Enable)
	assert.Equal(t, monitoringSecretName(testName), cfg.MonitoringUserSecret)
	assert.Empty(t, cfg.ScrapeInterval)
}

func TestSyncMonitoringUser(t *testing.T) {
	t.Run("creates role, user and mapping, and stores a generated password", func(t *testing.T) {
		var gotPaths []string
		withTestOpenSearchClient(t, func(w http.ResponseWriter, r *http.Request) {
			gotPaths = append(gotPaths, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		})
		c, cl := newTestContext(t, testInstance(validEngine()))

		err := syncMonitoringUser(c)

		require.NoError(t, err)
		require.ElementsMatch(t, []string{
			"/_plugins/_security/api/roles/" + monitoringRoleName,
			"/_plugins/_security/api/internalusers/" + monitoringUsername,
			"/_plugins/_security/api/rolesmapping/" + monitoringRoleName,
		}, gotPaths)

		secret := &corev1.Secret{}
		require.NoError(t, cl.Get(c.Context(), client.ObjectKey{Namespace: testNamespace, Name: monitoringSecretName(testName)}, secret))
		assert.Equal(t, monitoringUsername, string(secret.Data["username"]))
		assert.NotEmpty(t, secret.Data["password"])
	})

	t.Run("reuses an existing password on a later sync", func(t *testing.T) {
		var gotPasswords []string
		withTestOpenSearchClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/_plugins/_security/api/internalusers/"+monitoringUsername {
				var body map[string]any
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				gotPasswords = append(gotPasswords, body["password"].(string))
			}
			w.WriteHeader(http.StatusOK)
		})
		c, _ := newTestContext(t, testInstance(validEngine()))

		require.NoError(t, syncMonitoringUser(c))
		require.NoError(t, syncMonitoringUser(c))

		require.Len(t, gotPasswords, 2)
		assert.Equal(t, gotPasswords[0], gotPasswords[1])
	})

	t.Run("cluster not reachable yet is a no-op, not an error", func(t *testing.T) {
		c, _ := newTestContext(t, testInstance(validEngine()))

		err := syncMonitoringUser(c)

		require.NoError(t, err)
	})
}
