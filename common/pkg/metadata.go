package common

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	labelValuePartOf    = "part-of-change-me"
	labelValueComponent = "component-change-me"
)

func SanitizeLabelValue(value string) string {
	// K8s label values must be <= 63 chars, start/end with alphanumeric
	// and contain only alphanumeric, '-', '_', '.'

	if len(value) == 0 {
		return "unknown"
	}

	// Replace invalid characters
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, value)

	// Ensure it starts and ends with alphanumeric
	safe = strings.Trim(safe, "-_.")
	if len(safe) == 0 {
		return "unknown"
	}

	// Truncate if too long
	if len(safe) > 63 {
		safe = safe[:60] + K8sHexHash(value, 1) // Add hash suffix for uniqueness
	}

	return safe
}

func BuildConfigMapSafeLabels(ctx context.Context, cl client.Client, ns string, labelValueManagedBy string) map[string]string {
	labels := map[string]string{
		"app.kubernetes.io/part-of":    labelValuePartOf,
		"app.kubernetes.io/managed-by": labelValueManagedBy,
		"app.kubernetes.io/component":  labelValueComponent,
	}

	pod, err := GetCurrentPod(ctx, cl, ns)
	if err != nil || pod == nil {
		labels[LabelManagerType] = "kubectl"
		return labels
	}
	top, hasTop, _ := ResolveTopController(ctx, cl, ns, pod)

	if hasTop {
		if mm, ok := ManagerFromLabels(ns, top.Labels, top.Annotations); ok {
			if mm.Type == "argo" {
				labels[LabelManagerType] = "argo"
				labels["codespace.dev/argo-app"] = mm.Name
				return labels
			}
			if mm.Type == "helm" {
				labels[LabelManagerType] = "helm"
				labels["codespace.dev/release"] = mm.Name
				return labels
			}
		}
	}

	if mm, ok := ManagerFromLabels(ns, pod.Labels, pod.Annotations); ok {
		if mm.Type == "argo" {
			labels[LabelManagerType] = "argo"
			labels["codespace.dev/argo-app"] = mm.Name
			return labels
		}
		if mm.Type == "helm" {
			labels[LabelManagerType] = "helm"
			labels["codespace.dev/release"] = mm.Name
			return labels
		}
	}

	// Heuristic fallback
	if _, ok := pod.Labels["helm.sh/chart"]; ok {
		labels[LabelManagerType] = "helm"
	} else {
		labels[LabelManagerType] = "kubectl"
	}
	return labels
}

/* ============================
   Sanitization & index
   ============================ */

// SanitizeLabelValue ensures label values are Kubernetes-compliant

// buildInstanceMetaIndex scans per-instance ConfigMaps and returns instanceID -> AnchorMeta.
func BuildInstanceMetaIndex(ctx context.Context, cl client.Client, partOf string) map[string]AnchorMeta {
	out := map[string]AnchorMeta{}

	var cms corev1.ConfigMapList
	sel := client.MatchingLabels{
		"app.kubernetes.io/part-of":   partOf,
		"app.kubernetes.io/component": "server",
	}
	if err := cl.List(ctx, &cms, sel); err != nil {
		GetLogger().Debug("buildInstanceMetaIndex: list configmaps failed", "err", err)
		return out
	}

	for _, cm := range cms.Items {
		id := cm.Data["id"]
		if id == "" {
			continue
		}

		var meta AnchorMeta

		// 1) Prefer the stable anchor: "<kind>:<ns>:<name>"
		if a := cm.Data["anchor"]; a != "" {
			parts := strings.Split(a, ":")
			if len(parts) >= 3 {
				anchorType := parts[0]
				ns := parts[1]
				name := SanitizeLabelValue(parts[2])

				// recognize expanded set of anchorTypes
				if !recognizedAnchorType(anchorType) {
					anchorType = "unresolved"
					if name == "" {
						name = "unresolved"
					}
				}
				meta = AnchorMeta{Type: anchorType, Namespace: ns, Name: name}
			}
		}

		if meta.Type == "" {
			method := cm.Labels[LabelManagerType]
			switch method {
			case "helm":
				meta = AnchorMeta{Type: "helm", Namespace: cm.Namespace, Name: SanitizeLabelValue(cm.Labels["codespace.dev/release"])}
				if meta.Name == "" {
					meta.Name = "release"
				}
			case "argo":
				meta = AnchorMeta{Type: "argo", Namespace: cm.Namespace, Name: SanitizeLabelValue(cm.Labels["codespace.dev/argo-app"])}
				if meta.Name == "" {
					meta.Name = "app"
				}
			default:
				meta = AnchorMeta{Type: "unresolved", Namespace: cm.Namespace, Name: "unresolved"}
			}
		}

		out[id] = meta
	}

	return out
}
