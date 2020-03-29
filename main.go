package main

/*
 The SSH Certificate Authority Toolkit
*/

import (
	"log"
	"os"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "ssh-cert"
	app.Usage = "SSH Certificate Authority Toolkit"
	app.EnableBashCompletion = true
	app.Version = "0.1"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config, c",
			Usage: "Load configuration from `FILE`",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:   "sign",
			Usage:  "Sign user certificates for environments",
			Flags:  signFlags(),
			Action: sign,
		},
		{
			Name:   "server",
			Usage:  "Run the API Server",
			Flags:  serverFlags(),
			Action: runServer,
		},
		{
			Name:   "test",
			Usage:  "Test the configuration file to ensure it follows standards.",
			Flags:  configTestFlags(),
			Action: configTest,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
