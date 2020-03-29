package main

/*
 Run a API server for signing public keys.
*/

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
)

// Flags for the server command.
func serverFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{Name: "bind, b"},
		cli.UintFlag{Name: "port, p"},
	}
}

// We need to read the server configuration on each request. So the server functions are apart of a http server struct.
type httpServer struct {
	config Config
}

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

// Standard function to send JSON responses.
func (s httpServer) JSONResponse(w http.ResponseWriter, resp interface{}) {
	js, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

// The sign request handler.
func (s httpServer) SignHandler(w http.ResponseWriter, r *http.Request) {
	resp := httpSignResponse{}

	// We only allow POST method with a JSON body.
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	// Read the JSON body.
	decoder := json.NewDecoder(r.Body)
	var sr httpSignRequest
	err := decoder.Decode(&sr)
	if err != nil {
		resp.Successful = false
		resp.Message = err.Error()
		s.JSONResponse(w, resp)
		return
	}

	// Find the environment in the request.
	for _, environment := range s.config.Evironments {
		// Only if API key matches and the environment allows API requests.
		if environment.Name == sr.Environment && environment.APIServer && environment.APIKey == sr.APIKey {
			// Verify that the requested type is allowed in this environment.
			if sr.Type == "host" && !environment.HostKey {
				continue
			} else if sr.Type == "user" && !environment.UserKey {
				continue
			}

			// If the environment has a whitelist, verify the IP address of the request is whitelisted.
			if len(environment.APIWhitelist) >= 1 {
				allowed := false

				clientIP := strings.Split(r.RemoteAddr, ":")[0]
				// We recommend running the server behind a Nginx proxy with SSL.
				// This X-Forwarded-For section is a security risk if not behind Nginx.
				if r.Header.Get("X-Forwarded-For") != "" {
					forwardedIPs := strings.Split(r.Header.Get("X-Forwarded-For"), ", ")
					clientIP = forwardedIPs[len(forwardedIPs)-1]
				}

				for _, ipAddr := range environment.APIWhitelist {
					if strings.Contains(ipAddr, "/") {
						_, subnet, _ := net.ParseCIDR(ipAddr)
						ip := net.ParseIP(clientIP)
						if subnet.Contains(ip) {
							allowed = true
							break
						}
					} else if ipAddr == clientIP {
						allowed = true
						break
					}
				}

				// If IP address of client does not match whitelisted IP addresses.
				if !allowed {
					resp.Successful = false
					resp.Message = clientIP + " is Forbidden"
					s.JSONResponse(w, resp)
					return
				}
			}

			// Read the environment's private key.
			privKeyFile, err := ioutil.ReadFile(environment.CAKeyFile)
			if err != nil {
				log.Printf("Unable to read private key: %v", err)
				resp.Successful = false
				resp.Message = "Unable to read private key."
				s.JSONResponse(w, resp)
				return
			}

			// Create the Signer for this private key.
			authority, err := ssh.ParsePrivateKey(privKeyFile)
			if err != nil {
				log.Printf("Unable to read private key: %v", err)
				resp.Successful = false
				resp.Message = "Unable to read private key."
				s.JSONResponse(w, resp)
				return
			}

			// Current time used for validation date range.
			now := time.Now()

			// Get options for sign request.
			options := environment.SignOptions.Options
			if environment.SignOptions.AllowAPIOverrideOptions && len(sr.Options) != 0 {
				options = sr.Options
			}
			extensions := environment.SignOptions.Extensions
			if environment.SignOptions.AllowAPIOverrideExtensions && len(sr.Extensions) != 0 {
				options = sr.Extensions
			}
			keyID := environment.SignOptions.KeyID
			if environment.SignOptions.AllowAPIOverrideKeyID && len(sr.KeyID) != 0 {
				keyID = sr.KeyID
			}
			validPrincipals := environment.SignOptions.ValidPrincipals
			if environment.SignOptions.AllowAPIOverrideValidPrincipals && len(sr.ValidPrincipals) != 0 {
				validPrincipals = sr.ValidPrincipals
			}
			var certType uint32 = ssh.HostCert
			if sr.Type == "user" {
				certType = ssh.UserCert
			}
			duration := environment.SignOptions.Duration
			if environment.SignOptions.AllowAPIOverrideDuration && sr.Duration != 0 {
				duration = sr.Duration
			}

			for _, publicKey := range sr.PublicKeys {
				// Read the provided public key.
				pubKey, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(publicKey))
				if err != nil {
					log.Printf("Unable to read public key: %v %v", err, publicKey)
					resp.Successful = false
					resp.Message = "Unable to read public key."
					s.JSONResponse(w, resp)
					return
				}
				if len(rest) > 0 {
					log.Printf("rest: got %q, want empty %v", rest, publicKey)
					resp.Successful = false
					resp.Message = "Unable to read public key."
					s.JSONResponse(w, resp)
					return
				}

				// Create certificate.
				cert := &ssh.Certificate{
					Key:             pubKey,
					Serial:          0,
					CertType:        certType,
					KeyId:           keyID,
					ValidPrincipals: validPrincipals,
					ValidAfter:      uint64(now.Add(-10 * time.Minute).Unix()),
					ValidBefore:     uint64(now.Add(time.Second * duration).Unix()),
					Permissions: ssh.Permissions{
						CriticalOptions: options,
						Extensions:      extensions,
					},
				}

				// Sign the certificate.
				cert.SignCert(rand.Reader, authority)

				// Get the signed certificate in an authorized key format.
				data := ssh.MarshalAuthorizedKey(cert)
				resp.SignedKeys = append(resp.SignedKeys, string(data))
			}

			// Provide response.
			resp.Successful = true
			s.JSONResponse(w, resp)

			return
		}
	}

	// No environment was found that matches the request.
	resp.Successful = false
	resp.Message = "No environment found."
	s.JSONResponse(w, resp)
}

// Start the server with provided options.
func runServer(c *cli.Context) error {
	config := initConfig(c)

	// Get the configuration/
	bindAddr := config.BindAddr
	port := config.Port
	if c.String("bind") != "" {
		bindAddr = c.String("bind")
	}
	if c.Uint("port") != 0 {
		port = c.Uint("port")
	}

	// Create the server.
	server := httpServer{}
	server.config = config

	// Set the handlers.
	http.HandleFunc("/sign", server.SignHandler)

	// Start the server.
	fmt.Println("Starting server on port", port)
	err := http.ListenAndServe(fmt.Sprintf("%s:%d", bindAddr, port), nil)
	return err
}
