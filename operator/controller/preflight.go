package controller

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

var nonDNS = regexp.MustCompile(`[^a-z0-9-]+`)

func jobName(cr *v1.WatchtowerCluster, kind string) string {
	n := nonDNS.ReplaceAllString(strings.ToLower(cr.Name+"-"+kind+"-"+cr.Spec.Version), "-")
	if len(n) > 63 {
		n = strings.Trim(n[:63], "-")
	}
	return n
}

// jobFromApi builds a one-shot Job that runs `wtctl args...` with the api Deployment's pod
// template (image, env and Secret references, service account, security context) at the new
// version, so the operator never needs to know the database credentials itself.
func (r *Reconciler) jobFromApi(ctx context.Context, cr *v1.WatchtowerCluster, kind string, args []string) (*batchv1.Job, error) {
	ds, err := r.deployments(ctx, cr)
	if err != nil {
		return nil, err
	}
	for i := range ds {
		if service(&ds[i]) != "api" || len(ds[i].Spec.Template.Spec.Containers) == 0 {
			continue
		}
		spec := ds[i].Spec.Template.Spec.DeepCopy()
		spec.Containers = spec.Containers[:1]
		c := &spec.Containers[0]
		c.Name = kind
		c.Image = withTag(c.Image, cr.Spec.Version)
		c.Command, c.Args = []string{"wtctl"}, args
		c.Ports, c.LivenessProbe, c.ReadinessProbe, c.StartupProbe = nil, nil, nil, nil
		spec.RestartPolicy = corev1.RestartPolicyNever
		zero := int32(0)
		return &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: jobName(cr, kind), Namespace: cr.Namespace,
				Labels: map[string]string{"app.kubernetes.io/instance": cr.Name + "-ops", "app.kubernetes.io/component": kind}},
			Spec: batchv1.JobSpec{BackoffLimit: &zero, Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app.kubernetes.io/component": kind}},
				Spec:       *spec}},
		}, nil
	}
	return nil, errors.New("no api Deployment found to copy the pod template from")
}

// runJob creates the Job when absent (a restart of the operator resumes the same Job) and waits
// for it. A failed Job stays failed until an operator deletes it; the cluster stays Degraded.
func (r *Reconciler) runJob(ctx context.Context, cr *v1.WatchtowerCluster, kind string, args []string) error {
	jobs := r.KC.BatchV1().Jobs(cr.Namespace)
	name := jobName(cr, kind)
	if _, err := jobs.Get(ctx, name, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		j, err := r.jobFromApi(ctx, cr, kind, args)
		if err != nil {
			return err
		}
		if _, err := jobs.Create(ctx, j, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create %s job: %w", kind, err)
		}
	} else if err != nil {
		return fmt.Errorf("get %s job: %w", kind, err)
	}
	deadline := r.Now().Add(r.StepTimeout)
	for {
		j, err := jobs.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get %s job: %w", kind, err)
		}
		if j.Status.Succeeded > 0 {
			return nil
		}
		if j.Status.Failed > 0 {
			return fmt.Errorf("%s job %s failed", kind, name)
		}
		if err := r.sleep(ctx, deadline, kind+" job "+name); err != nil {
			return err
		}
	}
}

// sleep waits one poll interval, or returns an error at the deadline or when ctx ends.
func (r *Reconciler) sleep(ctx context.Context, deadline time.Time, what string) error {
	if !r.Now().Before(deadline) {
		return fmt.Errorf("timed out waiting for %s", what)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(r.Poll):
		return nil
	}
}

// preflight runs `wtctl upgrade preflight` (schema compatibility, free disk, Kafka reachable).
func (r *Reconciler) preflight(ctx context.Context, cr *v1.WatchtowerCluster) error {
	if err := r.runJob(ctx, cr, "preflight", []string{"upgrade", "preflight"}); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	return nil
}

// migrate runs `wtctl migrate`; schema changes are never rolled back automatically.
func (r *Reconciler) migrate(ctx context.Context, cr *v1.WatchtowerCluster) error {
	if err := r.runJob(ctx, cr, "migrate", []string{"migrate"}); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}
