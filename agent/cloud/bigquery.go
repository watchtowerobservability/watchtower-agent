package cloud

// BigQuery: the "bigquery" preset of the GCP pull expands to job, slot, storage and billed-bytes
// metrics (names land as cloud.gcp.bigquery.*, see gcpName).
func init() {
	gcpPresets["bigquery"] = []string{
		"bigquery.googleapis.com/job/num_in_flight",
		"bigquery.googleapis.com/slots/allocated_for_project",
		"bigquery.googleapis.com/storage/stored_bytes",
		"bigquery.googleapis.com/query/scanned_bytes_billed",
		"bigquery.googleapis.com/query/count",
	}
}
