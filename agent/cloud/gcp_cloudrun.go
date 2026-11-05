package cloud

// Cloud Run (INF-024): the "cloud_run" preset of the GCP pull expands to Cloud Run service and
// job metrics, and series of the cloud_run_revision and cloud_run_job resources are stamped
// with the FaaS attributes the serverless views filter on (cloud.platform gcp_cloud_run,
// faas.name, faas.version). Distribution metrics (latencies, utilizations) report their mean.

var gcpPresets = map[string][]string{
	"cloud_run": {
		"run.googleapis.com/request_count",
		"run.googleapis.com/request_latencies",
		"run.googleapis.com/container/instance_count",
		"run.googleapis.com/container/billable_instance_time",
		"run.googleapis.com/container/cpu/utilizations",
		"run.googleapis.com/container/memory/utilizations",
		"run.googleapis.com/container/startup_latencies",
		"run.googleapis.com/job/completed_execution_count",
		"run.googleapis.com/job/completed_task_attempt_count",
		"run.googleapis.com/job/running_executions",
		"run.googleapis.com/job/running_task_attempts",
	},
	// Pub/Sub backlog in messages and in time (oldest unacked age), dead letters and expired acks.
	"pubsub": {
		"pubsub.googleapis.com/subscription/num_undelivered_messages",
		"pubsub.googleapis.com/subscription/oldest_unacked_message_age",
		"pubsub.googleapis.com/subscription/dead_letter_message_count",
		"pubsub.googleapis.com/subscription/expired_ack_deadlines_count",
		"pubsub.googleapis.com/subscription/ack_message_count",
		"pubsub.googleapis.com/topic/send_message_operation_count",
	},
}

// expandPresets appends the metrics of each named preset (from table) that are not already listed.
func expandPresets(table map[string][]string, metrics, presets []string) []string {
	have := map[string]bool{}
	for _, m := range metrics {
		have[m] = true
	}
	for _, p := range presets {
		for _, m := range table[p] {
			if !have[m] {
				have[m] = true
				metrics = append(metrics, m)
			}
		}
	}
	return metrics
}

// cloudRunResource adds the FaaS resource attributes of a Cloud Run series.
func cloudRunResource(resType string, labels, res map[string]string) {
	switch resType {
	case "cloud_run_revision":
		res["cloud.platform"], res["faas.name"], res["faas.version"] = "gcp_cloud_run", labels["service_name"], labels["revision_name"]
	case "cloud_run_job":
		res["cloud.platform"], res["faas.name"] = "gcp_cloud_run", labels["job_name"]
	default:
		return
	}
	if l := labels["location"]; l != "" {
		res["cloud.region"] = l
	}
}
