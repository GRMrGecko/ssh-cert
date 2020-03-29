package main

/*
 Signs all host keys.
*/

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/urfave/cli"
)

// Options available via a signing request.
type httpSignRequest struct {
	Environment     string
	APIKey          string
	Type            string
	KeyID           string
	ValidPrincipals []string
	Options         map[string]string
	Extensions      map[string]string
	PublicKeys      []string
	Duration        time.Duration
}

// The standard API responses.
type httpSignResponse struct {
	Successful bool
	Message    string
	SignedKeys []string
}

// Flags for the sign command.
func signFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{Name: "key, k"},
	}
}

// The sign command calls this function.
func sign(c *cli.Context) error {
	// Load the configuration.
	config := initConfig(c)
	// If we want to just sign a single key, pass it via the argument.
	hostKey := c.String("key")

	// All host key files.
	var hostKeys []string

	// If a host key file was provided, we just use it. Otherwise we find system host keys.
	if hostKey != "" {
		hostKeys = append(hostKeys, hostKey)
	} else {
		// Host keys are stored in /etc/ssh/.
		files, err := ioutil.ReadDir("/etc/ssh/")
		if err != nil {
			return err
		}

		// Host keys end in .pub, but are not certificates.
		for _, f := range files {
			if strings.Contains(f.Name(), ".pub") && !strings.Contains(f.Name(), "-cert") && f.Name() != "ssh_host_key.pub" {
				hostKeys = append(hostKeys, "/etc/ssh/"+f.Name())
			}
		}
	}

	// Setup a signing request.
	sr := httpSignRequest{}
	sr.Environment = config.SignOptions.Environment
	sr.APIKey = config.SignOptions.APIKey
	sr.Type = "host"
	sr.KeyID = config.SignOptions.KeyID
	sr.Duration = config.SignOptions.Duration

	// If a key ID is not set in the configuration, we will use the hostname.
	if sr.KeyID == "" {
		sr.KeyID, _ = os.Hostname()
	}

	// Read the host keys into the signing request.
	for _, hostKey := range hostKeys {
		// Read the host public key.
		pubKeyFile, err := ioutil.ReadFile(hostKey)
		if err != nil {
			return fmt.Errorf("Unable to read public key: %v", err)
		}

		sr.PublicKeys = append(sr.PublicKeys, string(pubKeyFile))
	}

	// Convert signing request into JSON for the request.
	srData, err := json.Marshal(sr)
	if err != nil {
		return err
	}

	// Setup request.
	req, _ := http.NewRequest("POST", config.CertServer+"/sign", bytes.NewBuffer(srData))
	req.Header.Add("content-type", "application/json")

	// Send the request.
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// Parse the response.
	var signResponse httpSignResponse
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&signResponse)
	if err != nil {
		return err
	}

	// If successful, we need to pull the signed keys and store them/update the sshd configurations.
	if signResponse.Successful {
		// The configuration file path.
		sshdConfig := "/etc/ssh/sshd_config"

		// Open the sshd_config file.
		sshdConfigFile, err := os.Open(sshdConfig)
		if err != nil {
			return err
		}
		defer sshdConfigFile.Close()
		configReader := bufio.NewReader(sshdConfigFile)

		// We save our changes to the _new configuration file temporarily during edits.
		newConfig, err := os.Create(sshdConfig + "_new")
		if err != nil {
			return err
		}

		// We go through the file until all host key configurations are found.
		//  Once found, we then insert our certificate configurations.
		foundHostKeys := false
		// This is the last line read that is not a host key configuration.
		//  We need to write this line after adding the certificate configurations.
		var lastReadLine string
		for {
			// Read a line.
			line, err := configReader.ReadString('\n')

			// If end of line, we are done reading.
			if err == io.EOF {
				break
			}
			// If error, something is wrong.
			if err != nil {
				return err
			}

			// Configurations in sshd_config is white space separated. If a whitepsace is not found, it is not a configuration line.
			i := strings.IndexByte(line, ' ')
			if i != -1 {
				// We pull the configuration name.
				conf := line[:i]

				// If we found the host keys already, we check to see if this line is another host key or host certificate.
				//  If it is not, we are done reading at this point and we need to store the line for writing after we isnert our config.
				if foundHostKeys && conf != "HostKey" && conf != "HostCertificate" {
					lastReadLine = line
					break
				}
				// If this is a host certificate configuration, we need to ignore it.
				if conf == "HostCertificate" {
					continue
				}
				// If this is a host key configuration, we need to set the fact we found the host key configurations.
				if conf == "HostKey" {
					foundHostKeys = true
				}
			}
			// Write this line to the new configuration.
			newConfig.WriteString(line)
		}

		// Go through each of the signed keys, and save them/add to the sshd configuration.
		for i, signedKey := range signResponse.SignedKeys {
			// The signed key result should be in the same order we sent them,
			//  that means that the host key files will be in the same order.
			// The name of the host certificate file is the same as the public key,
			//   but with `-cert` pre-pended to the extension.
			certKeyFile := strings.Replace(hostKeys[i], ".pub", "-cert.pub", 1)

			// Save the certificate file.
			f, err := os.Create(certKeyFile)
			if err != nil {
				return err
			}
			f.WriteString(signedKey)
			f.Close()
			os.Chmod(certKeyFile, 0644)

			// Append to the new sshd configuration file the certificate configuration.
			newConfig.WriteString("HostCertificate " + certKeyFile + "\n")
		}

		// Append the line we last read before we inserted our host certificates.
		newConfig.WriteString(lastReadLine)
		for {
			// Read the next line available.
			line, err := configReader.ReadString('\n')

			// If end of line, we are done reading.
			if err == io.EOF {
				break
			}
			// If error, something is wrong.
			if err != nil {
				return err
			}

			// Configurations in sshd_config is white space separated. If a whitepsace is not found, it is not a configuration line.
			i := strings.IndexByte(line, ' ')
			if i != -1 {
				// We pull the configuration name.
				conf := line[:i]

				// If this is a host certificate configuration, we need to ignore it.
				if conf == "HostCertificate" {
					continue
				}
			}

			// Write line to the new sshd configuration file.
			newConfig.WriteString(line)
		}

		// We can finialize the new configuration file and replace the old one.
		newConfig.Close()
		err = os.Rename(sshdConfig+"_new", sshdConfig)
		if err != nil {
			return err
		}

		// We need the PID of sshd so that we can signal it to re-load its configuration file.
		pidB, err := ioutil.ReadFile("/var/run/sshd.pid")
		if err != nil {
			return err
		}
		pid, err := strconv.Atoi(string(pidB[:len(pidB)-1]))
		if err != nil {
			return err
		}

		// Find the active process for SSHD based on its pid.
		sshd, err := os.FindProcess(pid)
		if err != nil {
			return err
		}
		// Signal SSHD to reload its configuration file.
		sshd.Signal(syscall.SIGHUP)
	} else {
		// The request was not successful, so there is likely a message with an error.
		fmt.Println(signResponse.Message)
	}

	return nil
}
