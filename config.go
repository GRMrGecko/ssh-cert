package main

import (
	"fmt"
	"log"
	"net"
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
	BindAddr string `default:""`
	Port     uint   `default:"7789"`

	KeyDefaults struct {
		Type  string `default:"OKP"`
		Curve string `default:"Ed25519"`
		Size  int    `default:"2048"`
	}

	Evironments []struct {
		Name         string `required:"true"`
		CAKeyFile    string `required:"true"`
		SystemGroup  string
		APIServer    bool `default:"false"`
		APIKey       string
		APIWhitelist []string
		HostKey      bool `default:"false"`
		UserKey      bool `default:"false"`

		SignOptions struct {
			KeyID                           string `default:"USERNAME"`
			AllowAPIOverrideKeyID           bool   `default:"false"`
			ValidPrincipals                 []string
			AllowAPIOverrideValidPrincipals bool `default:"false"`
			Options                         map[string]string
			AllowAPIOverrideOptions         bool `default:"false"`
			Extensions                      map[string]string
			AllowAPIOverrideExtensions      bool          `default:"false"`
			Duration                        time.Duration `default:"3600"`
			AllowAPIOverrideDuration        bool          `default:"false"`
		}
	}
}

// Load the configuration.
func initConfig(c *cli.Context) Config {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	// Configuration paths.
	localConfig, _ := filepath.Abs("./config.json")
	homeDirConfig := usr.HomeDir + "/.config/ssh-ca/config.json"
	etcConfig := "/etc/ssh-ca/config.json"

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
	if config.Port == 0 {
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

	if config.BindAddr != "" && net.ParseIP(config.BindAddr) == nil {
		fmt.Println("Invalid bind address.")
		foundError = true
	}

	if config.Port > 65535 {
		fmt.Println("Invalid port number.")
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

	for _, environment := range config.Evironments {
		if !validName.MatchString(environment.Name) {
			fmt.Println("Invalid environment name:", environment.Name)
			foundError = true
		}

		if environment.SystemGroup != "" && !validName.MatchString(environment.SystemGroup) {
			fmt.Println("Invalid environment system group:", environment.SystemGroup)
			foundError = true
		}

		if _, err := os.Stat(environment.CAKeyFile); err != nil {
			fmt.Println("Key file does not exist:", environment.CAKeyFile)
			foundError = true
		}
	}

	if !foundError {
		fmt.Println("All configurations appear to be fine.")
	}

	return nil
}
