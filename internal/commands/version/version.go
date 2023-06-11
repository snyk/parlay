package version

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func GetVersion(logger zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:                   "version",
		Short:                 "Commands for using parlay with Snyk",
		Aliases:               []string{"s"},
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
		Run: func(cmd *cobra.Command, args []string) {

			type Tag struct {
				Name string `json:"name"`
			}

			repoURL := "https://api.github.com/repos/snyk/parlay/tags"

			// Send GET request to the GitHub API
			response, err := http.Get(repoURL)
			if err != nil {
				fmt.Printf("Error sending request: %s\n", err.Error())
				return
			}
			defer response.Body.Close()

			// Read the response body
			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				fmt.Printf("Error reading response: %s\n", err.Error())
				return
			}

			// Parse the JSON response
			var tags []Tag
			err = json.Unmarshal(body, &tags)
			if err != nil {
				fmt.Printf("Error parsing JSON: %s\n", err.Error())
				return
			}

			// Get the latest tag name
			if len(tags) > 0 {
				latestTag := tags[0].Name
				fmt.Sprintf("The current version of the parlay is : %s ", string(latestTag))
			} else {
				fmt.Println("No tags found for the repository.")
			}

		},
	}

	return &cmd
}
