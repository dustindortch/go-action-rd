package main

import (
	"fmt"

	"github.com/sethvargo/go-githubactions"
)

var Name string

func init() {
	Name = githubactions.GetInput("name")
	if Name == "" {
		githubactions.Fatalf("missing input 'name'")
	}
}

func main() {
	greeting := fmt.Sprintf("Hello, %v!", Name)
	githubactions.SetOutput("greeting", greeting)
}
