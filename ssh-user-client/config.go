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

	KeyDefaults struct {
		Type  string `default:"OKP"`
		Curve string `default:"Ed25519"`
		Size  int    `default:"2048"`
	}

	Evironments []struct {
		Name        string `required:"true"`
		SystemGroup string
		APIKey      string

		SignOptions struct {
			KeyID           string `default:"USERNAME"`
			ValidPrincipals []string
			Options         map[string]string
			Extensions      map[string]string
			Duration        time.Duration
		}
	}

	SignOptions struct {
		Environment     string
		APIKey          string
		KeyPath         string
		UID             int
		GID             int
		KeyID           string
		ValidPrincipals []string
		Options         map[string]string
		Extensions      map[string]string
		Duration        time.Duration
	}
}

// Load the configuration.
func initConfig(c *cli.Context) Config {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	// Configuration paths.
	localConfig, _ := filepath.Abs("./user-client.json")
	homeDirConfig := usr.HomeDir + "/.config/ssh-ca/user-client.json"
	etcConfig := "/etc/ssh-ca/user-client.json"

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

	switch config.KeyDefaults.Type {
	case "EC":
		switch config.KeyDefaults.Curve {
		case "P-256":
		case "P-384":
		case "P-521":
			// We are valid.
			break
		default:
			fmt.Println("Invalid curve setting in KeyDefaults.")
			foundError = true
		}
		break
	case "RSA":
		switch config.KeyDefaults.Size {
		case 512:
		case 1024:
		case 2048:
		case 4096:
		case 8192:
		case 16384:
			// We are valid.
			break
		default:
			fmt.Println("Invalid size setting in KeyDefaults.")
			foundError = true
		}
		break
	case "OKP":
		if config.KeyDefaults.Curve != "Ed25519" {
			fmt.Println("Invalid curve setting in KeyDefaults.")
			foundError = true
		}
		break
	case "oct":
		// We are valid.
		break
	default:
		fmt.Println("Invalid key type in KeyDefaults.")
		foundError = true
	}

	var validName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

	if len(config.Evironments) != 0 {
		for _, environment := range config.Evironments {
			if !validName.MatchString(environment.Name) {
				fmt.Println("Invalid environment name:", environment.Name)
				foundError = true
			}

			if environment.SystemGroup != "" && !validName.MatchString(environment.SystemGroup) {
				fmt.Println("Invalid environment system group:", environment.SystemGroup)
				foundError = true
			}
		}
	} else if config.SignOptions.KeyPath != "" {
		if !validName.MatchString(config.SignOptions.Environment) {
			fmt.Println("Invalid environment name")
			foundError = true
		}
	} else {
		fmt.Println("There has to be some key signing configuration, rather it be in SignOptions or Environments.")
		foundError = true
	}

	if !foundError {
		fmt.Println("All configurations appear to be fine.")
	}

	return nil
}
