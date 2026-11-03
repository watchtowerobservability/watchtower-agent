package autoinst

const iisSection = "-section:system.applicationHost/applicationPools"

// IISArgs is the appcmd argument list that adds one environment variable to a pool (IIS 10+).
// Names and values were validated (no quotes or brackets), so appcmd's syntax cannot break.
func IISArgs(pool, key, value string) []string {
	return []string{"set", "config", iisSection,
		"/+[name='" + pool + "'].environmentVariables.[name='" + key + "',value='" + value + "']",
		"/commit:apphost"}
}

// IISRemoveArgs removes one variable from a pool.
func IISRemoveArgs(pool, key string) []string {
	return []string{"set", "config", iisSection,
		"/-[name='" + pool + "'].environmentVariables.[name='" + key + "']",
		"/commit:apphost"}
}
