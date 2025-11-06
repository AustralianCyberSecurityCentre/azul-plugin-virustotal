package main

import (
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/cmd"
	_ "go.uber.org/automaxprocs"
)

func main() {
	cmd.Execute()
}
