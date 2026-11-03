package k8s

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Change history for NetworkPolicy and CustomResourceDefinition objects (INF-022). Both go
// through the same k8s.object.change log record as workload spec changes.

// NetpolAttrs describes a NetworkPolicy spec as the facts logged on change: its types, rule
// counts and a short digest of the whole spec, so any edit to a rule shows up.
func NetpolAttrs(sp *netv1.NetworkPolicySpec) map[string]string {
	const p = "k8s.networkpolicy.spec."
	types := make([]string, 0, len(sp.PolicyTypes))
	for _, t := range sp.PolicyTypes {
		types = append(types, string(t))
	}
	b, _ := json.Marshal(sp)
	sum := sha256.Sum256(b)
	return map[string]string{
		p + "policy_types":  strings.Join(types, ","),
		p + "ingress_rules": strconv.Itoa(len(sp.Ingress)),
		p + "egress_rules":  strconv.Itoa(len(sp.Egress)),
		p + "digest":        hex.EncodeToString(sum[:6]),
	}
}

func (c *cluster) onNetpolChange(oldObj, newObj any) {
	o, ok1 := oldObj.(*netv1.NetworkPolicy)
	n, ok2 := newObj.(*netv1.NetworkPolicy)
	if ok1 && ok2 {
		c.logChange("networkpolicy", o, n, NetpolAttrs(&o.Spec), NetpolAttrs(&n.Spec))
	}
}

// onCRDChange logs a CRD whose generation moved (a schema or version change). Only metadata is
// watched, so the record carries the generation, not the schema.
func (c *cluster) onCRDChange(oldObj, newObj any) {
	o, ok1 := oldObj.(*metav1.PartialObjectMetadata)
	n, ok2 := newObj.(*metav1.PartialObjectMetadata)
	if !ok1 || !ok2 {
		return
	}
	g := func(m *metav1.PartialObjectMetadata) map[string]string {
		return map[string]string{"k8s.crd.spec.generation": strconv.FormatInt(m.Generation, 10)}
	}
	c.logChange("crd", o, n, g(o), g(n))
}

// watchCRDs starts a metadata-only informer on CustomResourceDefinitions (no schema is read or
// kept). It is best effort: a cluster that forbids it just has no CRD history.
func (c *cluster) watchCRDs(ctx context.Context, rc *rest.Config) error {
	mc, err := metadata.NewForConfig(rc)
	if err != nil {
		return err
	}
	gvr := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	inf := metadatainformer.NewFilteredMetadataInformer(mc, gvr, metav1.NamespaceAll, resyncPeriod, cache.Indexers{}, nil).Informer()
	if _, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{UpdateFunc: c.onCRDChange}); err != nil {
		return err
	}
	go inf.Run(ctx.Done())
	return nil
}
