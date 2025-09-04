package common

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	InstanceIDLabel        = "codespace.dev/instance-id"
	LabelCreatedBy         = "codespace.dev/created-by"     // hashed, label-safe
	AnnotationCreatedBy    = "codespace.dev/created-by"     // raw subject
	AnnotationCreatedBySig = "codespace.dev/created-by.sig" // optional: HMAC of raw subject
	ReleaseLabelKey        = "codespace.dev/release"
)

/*
	We backfill for existing sessions (cluster-scope) during list/stream:
	the server builds a map of instance-id -> manager meta by scanning the per-instance ConfigMaps it already creates (the ones named like codespace-server-instance-*)
	the server enriches each returned session with the same labels in-memory (no persistence needed).
*/
// Manager identity labels stamped on Session objects
var (
	LabelManagerType      = "codespace.dev/manager-type" // helm|argo|deployment|statefulset|namespace
	LabelManagerName      = "codespace.dev/manager-name" // release/app/deployment name (sanitized)
	LabelManagerNamespace = "codespace.dev/manager-ns"   // namespace the manager runs in
)

type topMeta struct {
	Kind        string
	Name        string
	Labels      map[string]string
	Annotations map[string]string
}

// AnchorMeta describes how an instance is managed.
type AnchorMeta struct {
	Type      string // argo|helm|deployment|statefulset|daemonset|cronjob|job|pod|namespace|unresolved
	Name      string // release/app/deployment name (sanitized when used as label)
	Namespace string // namespace where the manager runs
}

func (a AnchorMeta) String() string {
	// stable, parseable
	return fmt.Sprintf("%s:%s:%s", a.Type, a.Namespace, a.Name)
}
func recognizedAnchorType(anchorType string) bool {
	switch anchorType {
	case "helm", "argo", "deployment", "statefulset", "daemonset", "cronjob", "job", "pod", "namespace",
		"binary", "container", "local":
		return true
	default:
		return false
	}
}
func GetSelfAnchorMeta(ctx context.Context, cl client.Client) (anchorMeta AnchorMeta, rbacLimited bool, isKubernetes bool) {
	ns, isKubernetes := ResolveAnchorNamespace()
	if !isKubernetes {
		return localBinaryAnchor(ns), false, isKubernetes
	}

	pod, err := GetCurrentPod(ctx, cl, ns)
	if err != nil || pod == nil {
		GetLogger().Warn("GetSelfAnchorMeta: current pod not found", "namespace", ns, "err", err)
		return AnchorMeta{Type: "unresolved", Name: "unresolved", Namespace: ns}, false, isKubernetes
	}

	top, hasTop, rbacLimited := ResolveTopController(ctx, cl, ns, pod)

	// Prefer Argo/Helm from TOP labels (if we fetched labels)
	if hasTop && top.Labels != nil {
		if app := argoAppName(top.Labels, top.Annotations); app != "" {
			return AnchorMeta{Type: "argo", Name: SanitizeLabelValue(app), Namespace: ns}, rbacLimited, isKubernetes
		}
		if rel := helmReleaseName(top.Labels, top.Annotations); rel != "" {
			return AnchorMeta{Type: "helm", Name: SanitizeLabelValue(rel), Namespace: ns}, rbacLimited, isKubernetes
		}
	}

	// Try pod labels only when top didn't yield a manager (or labels unavailable)
	if app := argoAppName(pod.Labels, pod.Annotations); app != "" {
		return AnchorMeta{Type: "argo", Name: SanitizeLabelValue(app), Namespace: ns}, rbacLimited, isKubernetes
	}
	if rel := helmReleaseName(pod.Labels, pod.Annotations); rel != "" {
		return AnchorMeta{Type: "helm", Name: SanitizeLabelValue(rel), Namespace: ns}, rbacLimited, isKubernetes
	}

	// Fall back to top identity (even if it came from OwnerRef only)
	if hasTop && top.Kind != "" && top.Name != "" {
		return AnchorMeta{Type: top.Kind, Name: SanitizeLabelValue(top.Name), Namespace: ns}, rbacLimited, isKubernetes
	}

	// Finally: pod identity
	return AnchorMeta{Type: "pod", Name: SanitizeLabelValue(pod.Name), Namespace: ns}, rbacLimited, isKubernetes
}
func anchorOverride(meta AnchorMeta) (AnchorMeta, bool) {
	if t := strings.TrimSpace(os.Getenv("CODESPACE_ANCHOR_TYPE")); t != "" {
		name := SanitizeLabelValue(os.Getenv("CODESPACE_ANCHOR_NAME"))
		ns := SanitizeLabelValue(os.Getenv("CODESPACE_ANCHOR_NS"))
		if name == "" {
			name = "unresolved"
		}
		if ns == "" {
			ns = "local"
		}
		return AnchorMeta{Type: strings.ToLower(t), Name: name, Namespace: ns}, true
	}
	return AnchorMeta{}, false
}

// Enhanced Kubernetes detection with multiple fallback checks
func inKubernetes() bool {
	// Check environment variables
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" || os.Getenv("KUBERNETES_PORT") != "" {
		return true
	}

	// Check for service account token (most reliable indicator)
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}

	// Check for service account namespace file
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		return true
	}

	// Check for service account ca.crt
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"); err == nil {
		return true
	}

	// Additional check: POD_NAME or POD_NAMESPACE env vars
	if os.Getenv("POD_NAME") != "" || os.Getenv("POD_NAMESPACE") != "" {
		return true
	}

	return false
}

// looksLocalOS returns a normalized “local platform” string.
// examples: "linux", "linux-wsl", "darwin", "windows"
func looksLocalOS() string {
	switch runtime.GOOS {
	case "linux":
		// Detect WSL
		if strings.Contains(strings.ToLower(readFileTrim("/proc/sys/kernel/osrelease")), "microsoft") {
			return "linux-wsl"
		}
		return "linux"
	case "darwin":
		return "darwin"
	case "windows":
		return "windows"
	default:
		return runtime.GOOS // keep something stable for other OSes
	}
}

func currentUsernameOrHost() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "local"
}

func currentExeName() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Base(exe)
	}
	return "process"
}

// ============================
// Anchor constructors
// ============================

func localBinaryAnchor(ns string) AnchorMeta {
	return AnchorMeta{
		Type:      "local",
		Name:      SanitizeLabelValue(currentExeName()),
		Namespace: SanitizeLabelValue(ns),
	}
}
func ManagerFromLabels(ns string, labels, ann map[string]string) (AnchorMeta, bool) {
	if app := argoAppName(labels, ann); app != "" {
		return AnchorMeta{Type: "argo", Name: SanitizeLabelValue(app), Namespace: ns}, true
	}
	if rel := helmReleaseName(labels, ann); rel != "" {
		return AnchorMeta{Type: "helm", Name: SanitizeLabelValue(rel), Namespace: ns}, true
	}
	return AnchorMeta{}, false
}

// Helm: prefer meta.helm.sh/release-name annotation.
// If absent, accept app.kubernetes.io/instance **only if** we see strong Helm signals.
func helmReleaseName(labels, ann map[string]string) string {
	if v := ann["meta.helm.sh/release-name"]; v != "" {
		return v
	}
	rel := labels["app.kubernetes.io/instance"]
	if rel == "" {
		return ""
	}
	// Guard against Argo collision by requiring Helm markers.
	if labels["app.kubernetes.io/managed-by"] == "Helm" || labels["helm.sh/chart"] != "" || ann["helm.sh/chart"] != "" {
		return rel
	}
	return ""
}

// We treat only argocd.argoproj.io/instance as Argo to avoid confusion with Helm's use of app.kubernetes.io/instance.
func argoAppName(labels, ann map[string]string) string {
	if v := labels["argocd.argoproj.io/instance"]; v != "" {
		return v
	}
	if v := ann["argocd.argoproj.io/instance"]; v != "" {
		return v
	}
	return ""
}

func GetClusterUID(ctx context.Context, cl client.Client) string {
	var ns corev1.Namespace
	if err := cl.Get(ctx, types.NamespacedName{Name: "kube-system"}, &ns); err == nil {
		return string(ns.UID)
	}
	if err := cl.Get(ctx, types.NamespacedName{Name: "default"}, &ns); err == nil {
		return string(ns.UID)
	}
	return "unknown"
}

// CLUSTER_UID=$(kubectl get ns kube-system -o jsonpath='{.metadata.uid}' 2>/dev/null || kubectl get ns default -o jsonpath='{.metadata.uid}'); \
// ANCHOR="helm:my-ns:my-release"; \
// printf 'i1-%s\n' "$(printf '%s' "$CLUSTER_UID|$ANCHOR" | sha256sum | awk '{print $1}')"
func InstanceIDv1(clusterUID string, anchor AnchorMeta) string {
	s := clusterUID + "|" + anchor.String()
	sum := sha256.Sum256([]byte(s))
	// 20 bytes -> 40 hex chars   (label-safe: 3 + 40 = 43)
	return "i1-" + hex.EncodeToString(sum[:20])
}
