package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"time"

	"github.com/jinzhu/configor"
	"github.com/urfave/cli"
)

// Configuration Structure.
type Config struct {
	CertServer string

	SignOptions struct {
		Environment string
		APIKey      string
		KeyID       string
		Duration    time.Duration
	}
}

// Load the configuration.
func initConfig(c *cli.Context) Config {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	// Configuration paths.
	localConfig, _ := filepath.Abs("./client.json")
	homeDirConfig := usr.HomeDir + "/.config/ssh-ca/client.json"
	etcConfig := "/etc/ssh-ca/client.json"

	// Determine which configuration to use.
	var configFile string
	if _, err := os.Stat(c.String("config")); err == nil {
		configFile = c.String("config")
	} else if _, err := os.Stat(localConfig); err == nil {
		configFile = localConfig
	} else if _, err := os.Stat(homeDirConfig); err == nil {
		configFile = homeDirConfig
	} else if _, err := os.Stat(etcConfig); err == nil {
		configFile = etcConfig
	} else {
		log.Fatal("Unable to find a configuration file.")
	}

	// Load the configuration file.
	config := Config{}
	err = configor.Load(&config, configFile)
	if config.CertServer == "" {
		fmt.Println(err)
		log.Fatal("Unable to load the configuration file.")
	}
	return config
}

// Flags for the server command.
func configTestFlags() []cli.Flag {
	return []cli.Flag{}
}

func configTest(c *cli.Context) error {
	config := initConfig(c)

	foundError := false

	if config.CertServer == "" {
		fmt.Println("Cert server address.")
		foundError = true
	}

	var validName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

	if !validName.MatchString(config.SignOptions.Environment) {
		fmt.Println("Invalid environment name")
		foundError = true
	}

	if !foundError {
		fmt.Println("All configurations appear to be fine.")
	}

	return nil
}
