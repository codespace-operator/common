package common

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestBuildInstanceMetaIndex(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	ns := "work"
	// CM1: stable anchor string wins
	cm1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "codespace-server-instance-1",
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/part-of":   labelValuePartOf,
				"app.kubernetes.io/component": "server",
			},
		},
		Data: map[string]string{
			"id":     "id-1",
			"anchor": "helm:prod:my-release",
		},
	}

	// CM2: no "anchor", infer from manager labels (helm)
	cm2 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "codespace-server-instance-2",
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/part-of":   labelValuePartOf,
				"app.kubernetes.io/component": "server",
				LabelManagerType:              "helm",
				ReleaseLabelKey:               "myrel",
			},
		},
		Data: map[string]string{
			"id": "id-2",
		},
	}

	// CM3: unknown → unresolved fallback
	cm3 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "codespace-server-instance-3",
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/part-of":   labelValuePartOf,
				"app.kubernetes.io/component": "server",
			},
		},
		Data: map[string]string{
			"id": "id-3",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm1, cm2, cm3).Build()
	idx := BuildInstanceMetaIndex(context.Background(), cl, labelValuePartOf)

	if got, ok := idx["id-1"]; !ok || got.Type != "helm" || got.Namespace != "prod" || got.Name != "my-release" {
		t.Fatalf("id-1 meta wrong: %+v", got)
	}
	if got := idx["id-2"]; got.Type != "helm" || got.Namespace != ns || got.Name != "myrel" {
		t.Fatalf("id-2 meta wrong: %+v", got)
	}
	if got := idx["id-3"]; got.Type != "unresolved" || got.Namespace != ns || got.Name != "unresolved" {
		t.Fatalf("id-3 meta wrong: %+v", got)
	}
}
