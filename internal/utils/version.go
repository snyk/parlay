package utils

// This value gets set at build time
var version string

func GetVersion() string {
	return version
}
