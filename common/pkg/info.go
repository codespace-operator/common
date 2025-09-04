package common

import "time"

func GetBuildInfo() map[string]string {
	// These would typically be injected at build time with -ldflags
	return map[string]string{
		"version":   "1.0.0",                         // -X main.Version=$(git describe --tags)
		"gitCommit": "abc123",                        // -X main.GitCommit=$(git rev-parse HEAD)
		"buildDate": time.Now().Format(time.RFC3339), // -X main.BuildDate=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
	}
}
