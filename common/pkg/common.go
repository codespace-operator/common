package common

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/spf13/viper"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var DEFAULT_NAMESPACE = "default"

// retryOnConflict runs fn with standard backoff if a 409 occurs.
func RetryOnConflict(fn func() error) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return fn()
	})
}

// buildKubeConfig creates a Kubernetes client config that works both locally and in-cluster
func BuildKubeConfig() (*rest.Config, error) {
	// 1. Try in-cluster config first (when running inside a pod)
	if cfg, err := rest.InClusterConfig(); err == nil {
		log.Println("Using in-cluster Kubernetes config")
		return cfg, nil
	}

	// 2. Try KUBECONFIG environment variable
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		log.Printf("Using KUBECONFIG from environment: %s", kubeconfig)
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	// 3. Try default kubeconfig location (~/.kube/config)
	if home := homedir.HomeDir(); home != "" {
		kubeconfig := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(kubeconfig); err == nil {
			log.Printf("Using default kubeconfig: %s", kubeconfig)
			return clientcmd.BuildConfigFromFlags("", kubeconfig)
		}
	}

	// 4. Try service account token (alternative in-cluster method)
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		log.Println("Using service account token")
		return rest.InClusterConfig()
	}

	return nil, fmt.Errorf("unable to create Kubernetes client config: tried in-cluster, KUBECONFIG, and ~/.kube/config")
}
func RandB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func Itoa(i int32) string { return fmt.Sprintf("%d", i) }

// setupViper configures common Viper settings.
// envPrefix: e.g. "CODESPACE_SERVER"
// fileBase:  e.g. "server-config" (-> server-config.yaml)
func SetupViper(v *viper.Viper, envPrefix, fileBase string) {
	// --- Environment (UPPER_SNAKE with prefix) ---
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// Logging helper (default logger only after logger is setup)
	now := func() string { return time.Now().Format(time.RFC3339) }
	log := func(f string, a ...any) {
		fmt.Fprintf(os.Stderr, now()+" "+f+"\n", a...)
	}

	// --- Single knob: <PREFIX>_CONFIG_DEFAULT_PATH (file OR directory) ---
	var dirOverride string
	if raw := strings.TrimSpace(os.Getenv(envPrefix + "_CONFIG_DEFAULT_PATH")); raw != "" {
		p := os.ExpandEnv(raw)

		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			// IMPORTANT: pass the DIRECTORY to AddConfigPath, not a file path.
			dirOverride = p // remember to search here first
		} else {
			// Treat as a FILE path (relative or absolute)
			if !filepath.IsAbs(p) {
				if abs, err := filepath.Abs(p); err == nil {
					p = abs
				}
			}
			if _, err := os.Stat(p); err != nil {
				panic(fmt.Errorf("%s_CONFIG_DEFAULT_PATH points to missing file: %s (err=%w)", envPrefix, p, err))
			}
			v.SetConfigFile(p)
			if err := v.ReadInConfig(); err != nil {
				panic(fmt.Errorf("failed to read %s_CONFIG_DEFAULT_PATH=%s: %w", envPrefix, p, err))
			}
			log("loaded config override (file): %s", v.ConfigFileUsed())
			return
		}
	}

	// --- Directory search mode ---
	v.SetConfigName(fileBase)
	v.SetConfigType("yaml")

	// If a dir override was provided, search it FIRST (can be relative)
	if dirOverride != "" {
		v.AddConfigPath(dirOverride)
	}

	// Default search locations (in order)
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/codespace-operator/")
	v.AddConfigPath("$HOME/.codespace-operator/")

	// Optional file - ignore if missing
	if err := v.ReadInConfig(); err == nil {
		log("loaded config (search): %s", v.ConfigFileUsed())
	} else {
		log("no config file found via search (env-only is fine)")
	}
}

func SplitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// StructToMapStringString converts any struct (or pointer to struct)
// into a flat map[string]string. Only exported fields are included.
func StructToMapStringString(v any) (map[string]string, error) {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil, errors.New("nil value")
	}
	// Dereference pointers
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil, errors.New("nil pointer")
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct, got %s", rv.Kind())
	}

	out := make(map[string]string)
	walkStruct(rv, "", out)
	return out, nil
}

func walkStruct(val reflect.Value, prefix string, out map[string]string) {
	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		sf := typ.Field(i)
		if sf.PkgPath != "" { // unexported
			continue
		}
		// Respect json tags
		name, ok := jsonFieldName(sf)
		if !ok {
			continue // tag "-"
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}

		fv := val.Field(i)
		// Deref pointers
		for fv.Kind() == reflect.Pointer {
			if fv.IsNil() {
				out[key] = ""
				goto nextField
			}
			fv = fv.Elem()
		}

		switch fv.Kind() {
		case reflect.Struct:
			// Special-case time.Time
			if fv.Type().PkgPath() == "time" && fv.Type().Name() == "Time" {
				out[key] = fv.Interface().(time.Time).Format(time.RFC3339)
			} else {
				walkStruct(fv, key, out)
			}
		case reflect.Slice, reflect.Array:
			var parts []string
			for j := 0; j < fv.Len(); j++ {
				parts = append(parts, fmt.Sprint(fv.Index(j).Interface()))
			}
			out[key] = strings.Join(parts, ",")
		case reflect.Map:
			// If it's a map with string keys, expand it; otherwise stringify.
			if fv.Type().Key().Kind() == reflect.String {
				keys := fv.MapKeys()
				sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
				for _, mk := range keys {
					subKey := key + "." + mk.String()
					out[subKey] = fmt.Sprint(fv.MapIndex(mk).Interface())
				}
			} else {
				out[key] = fmt.Sprint(fv.Interface())
			}
		default:
			out[key] = fmt.Sprint(fv.Interface())
		}
	nextField:
	}
}

func jsonFieldName(sf reflect.StructField) (string, bool) {
	tag := sf.Tag.Get("json")
	if tag == "-" {
		return "", false
	}
	if tag == "" {
		// For anonymous embedded structs without a tag, use their type name
		// (walkStruct will still recurse into them anyway).
		return sf.Name, true
	}
	parts := strings.Split(tag, ",")
	name := parts[0]
	if name == "" { // `json:",omitempty"`
		name = sf.Name
	}
	return name, true
}

func lowerKind(k string) string { return strings.ToLower(k) }

func K8sHexHash(s string, bytes int) string {
	if bytes <= 0 || bytes > 32 {
		bytes = 10 // 10 bytes -> 20 hex chars
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:bytes])
}

// SubjectToLabelID returns a stable, label-safe ID for a user/subject.
// Format: s256-<40 hex> (first 20 bytes of SHA-256 => 40 hex chars). Total length 45.
func SubjectToLabelID(sub string) string {
	if sub == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(sub))
	return "s256-" + hex.EncodeToString(sum[:20]) // 160-bit truncation; label-safe; <=63
}
func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func readFileTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
func GetDefaultContextNamespace() string {
	loader := clientcmd.NewDefaultClientConfigLoadingRules() // respects $KUBECONFIG and ~/.kube/config
	cfg, err := loader.Load()
	if err != nil || cfg == nil || cfg.CurrentContext == "" {
		return DEFAULT_NAMESPACE
	}
	ctx := cfg.Contexts[cfg.CurrentContext]
	if ctx == nil || ctx.Namespace == "" {
		return DEFAULT_NAMESPACE
	}
	return ctx.Namespace
}
func ResolveAnchorNamespace() (ns string, isKubernetes bool) {
	if inKubernetes() {
		return GetInClusterNamespace(), true
	}
	return GetDefaultContextNamespace(), false
}

// returns the single controller owner (if any)
func controllerOf(obj metav1.Object) *metav1.OwnerReference {
	for i := range obj.GetOwnerReferences() {
		or := obj.GetOwnerReferences()[i]
		if or.Controller != nil && *or.Controller {
			return &or
		}
	}
	return nil
}

// ResolveTopController walks up controller refs to the top controller it can see.
// It never errors out: it returns the best it can and a signal if RBAC likely limited us.
// - top: the best top object we could determine (labels/annos only present if fetched)
// - ok:  true if the pod had a controller (false => top is the pod)
// - rbacLimited: true if we hit Forbidden/Unauthorized anywhere during the walk
func ResolveTopController(ctx context.Context, cl client.Client, ns string, pod *corev1.Pod) (top topMeta, ok bool, rbacLimited bool) {
	if pod == nil {
		return topMeta{"pod", "", nil, nil}, false, false
	}
	ref := controllerOf(pod)
	if ref == nil {
		return topMeta{"pod", pod.Name, pod.Labels, pod.Annotations}, false, false
	}
	return followController(ctx, cl, ns, *ref)
}

func followController(ctx context.Context, cl client.Client, ns string, ref metav1.OwnerReference) (top topMeta, ok bool, rbacLimited bool) {
	switch ref.Kind {

	case "ReplicaSet":
		var rs appsv1.ReplicaSet
		if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &rs); err != nil {
			if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
				return topMeta{Kind: lowerKind(ref.Kind), Name: ref.Name}, true, true
			}
			// best-effort even on NotFound or other errors
			return topMeta{Kind: lowerKind(ref.Kind), Name: ref.Name}, true, false
		}
		// promote to its controller if present (Deployment, Rollout, etc.)
		if parent := controllerOf(&rs); parent != nil {
			// known fast-path: Deployment
			if parent.Kind == "Deployment" {
				var dep appsv1.Deployment
				err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: parent.Name}, &dep)
				if err == nil {
					return topMeta{"deployment", dep.Name, dep.Labels, dep.Annotations}, true, false
				}
				if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
					return topMeta{Kind: "deployment", Name: parent.Name}, true, true
				}
				return topMeta{Kind: "deployment", Name: parent.Name}, true, false
			}
			// generic for CRDs (e.g., argoproj.io Rollout)
			return followGeneric(ctx, cl, ns, *parent)
		}
		return topMeta{"replicaset", rs.Name, rs.Labels, rs.Annotations}, true, false

	case "StatefulSet":
		var ss appsv1.StatefulSet
		if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &ss); err != nil {
			if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
				return topMeta{Kind: "statefulset", Name: ref.Name}, true, true
			}
			return topMeta{Kind: "statefulset", Name: ref.Name}, true, false
		}
		return topMeta{"statefulset", ss.Name, ss.Labels, ss.Annotations}, true, false

	case "DaemonSet":
		var ds appsv1.DaemonSet
		if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &ds); err != nil {
			if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
				return topMeta{Kind: "daemonset", Name: ref.Name}, true, true
			}
			return topMeta{Kind: "daemonset", Name: ref.Name}, true, false
		}
		return topMeta{"daemonset", ds.Name, ds.Labels, ds.Annotations}, true, false

	case "Job":
		var job batchv1.Job
		if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &job); err != nil {
			if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
				return topMeta{Kind: "job", Name: ref.Name}, true, true
			}
			return topMeta{Kind: "job", Name: ref.Name}, true, false
		}
		// promote to CronJob when applicable
		if parent := controllerOf(&job); parent != nil && parent.Kind == "CronJob" {
			var cj batchv1.CronJob
			err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: parent.Name}, &cj)
			if err == nil {
				return topMeta{"cronjob", cj.Name, cj.Labels, cj.Annotations}, true, false
			}
			if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
				return topMeta{Kind: "cronjob", Name: parent.Name}, true, true
			}
			return topMeta{Kind: "cronjob", Name: parent.Name}, true, false
		}
		return topMeta{"job", job.Name, job.Labels, job.Annotations}, true, false

	case "ReplicationController":
		var rc corev1.ReplicationController
		err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &rc)
		if err != nil {
			if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
				return topMeta{Kind: "replicationcontroller", Name: ref.Name}, true, true
			}
			return topMeta{Kind: "replicationcontroller", Name: ref.Name}, true, false
		}
		return topMeta{"replicationcontroller", rc.Name, rc.Labels, rc.Annotations}, true, false

	default:
		// unknown kind (CRD) → best-effort generic
		return followGeneric(ctx, cl, ns, ref)
	}
}

func followGeneric(ctx context.Context, cl client.Client, ns string, ref metav1.OwnerReference) (top topMeta, ok bool, rbacLimited bool) {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind))
	if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, u); err != nil {
		if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
			return topMeta{Kind: lowerKind(ref.Kind), Name: ref.Name}, true, true
		}
		return topMeta{Kind: lowerKind(ref.Kind), Name: ref.Name}, true, false
	}
	// If it has a controller, keep walking
	if parent := controllerOf(u); parent != nil {
		return followGeneric(ctx, cl, ns, *parent)
	}
	return topMeta{Kind: lowerKind(ref.Kind), Name: u.GetName(), Labels: u.GetLabels(), Annotations: u.GetAnnotations()}, true, false
}

func GetCurrentPod(ctx context.Context, cl client.Client, ns string) (*corev1.Pod, error) {
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		var err error
		podName, err = os.Hostname()
		if err != nil {
			return nil, err
		}
	}
	var pod corev1.Pod
	if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: podName}, &pod); err != nil {
		return nil, err
	}
	return &pod, nil
}
func GetInClusterNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	if b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	return DEFAULT_NAMESPACE
}
