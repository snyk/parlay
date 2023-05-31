package deps

import (
	"github.com/edoardottt/depsdev/pkg/depsdev"
)

func GetRepoData(url string) (*depsdev.Project, error) {
	proj, err := depsdev.GetProject(url)
	if err != nil {
		return nil, err
	}
	return &proj, nil
}
