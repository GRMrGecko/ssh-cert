package main

/*
 Generates keys and signs keys for users in each environment.
*/

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
)

// Flags for the sign command.
func signFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{Name: "environment, e"},
	}
}

// Group and user data structure.
type Group struct {
	Name  string
	ID    uint64
	Users []string
}
type User struct {
	Name     string
	ID       uint64
	GID      uint64
	FullName string
	HomeDir  string
	Shell    string
	Disabled bool
}

// UNIX Accounts tool set designed to easily get a group or user's information.
type UNIXAccounts struct {
	Groups []*Group
	Users  []*User
}

// Read the /etc/group and /etc/passwd files to parse information.
func (u *UNIXAccounts) init() error {
	// We do not want to parse twice.
	if len(u.Groups) != 0 || len(u.Users) != 0 {
		return fmt.Errorf("Already parsed accounts.")
	}

	// Open the group file.
	groupFile, err := os.Open("/etc/group")
	if err != nil {
		return err
	}

	defer groupFile.Close()

	groupReader := bufio.NewReader(groupFile)
	for {
		// Read a line and truncate it.
		line, err := groupReader.ReadString('\n')
		line = strings.TrimSuffix(line, "\n")

		// If end of line, we are done reading.
		if err == io.EOF {
			break
		}
		// If error, something is wrong.
		if err != nil {
			return err
		}

		// Ignore comments.
		if line[0] == '#' {
			continue
		}

		// Fields are separated with a :.
		fields := strings.Split(line, ":")

		// Groups should have 4 fields. Nothing more, nothing less.
		if len(fields) != 4 {
			continue
		}

		// Parse information.
		group := new(Group)
		group.Name = fields[0]
		group.ID, _ = strconv.ParseUint(fields[2], 10, 32)
		group.Users = strings.Split(fields[3], ",")

		// Add group to array.
		u.Groups = append(u.Groups, group)
	}

	// Open the user file.
	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		return err
	}

	defer passwdFile.Close()

	passwdReader := bufio.NewReader(passwdFile)
	for {
		// Read a line and truncate it.
		line, err := passwdReader.ReadString('\n')
		line = strings.TrimSuffix(line, "\n")

		// If end of line, we are done.
		if err == io.EOF {
			break
		}
		// If error, something is wrong.
		if err != nil {
			return err
		}

		// Ignore comments.
		if line[0] == '#' {
			continue
		}

		// Fields are separated with a :.
		fields := strings.Split(line, ":")

		// Users have 7 fields. No more or less.
		if len(fields) != 7 {
			continue
		}

		// Prase information.
		user := new(User)
		user.Name = fields[0]
		user.ID, _ = strconv.ParseUint(fields[2], 10, 32)
		user.GID, _ = strconv.ParseUint(fields[3], 10, 32)
		user.FullName = fields[4]
		user.HomeDir = filepath.Clean(fields[5])
		user.Shell = fields[6]

		// A user is disabled if their shell is set to nologin or false. Users with no shell should also be disabled.
		user.Disabled = false
		if strings.Contains(user.Shell, "nologin") {
			user.Disabled = true
		}
		if strings.Contains(user.Shell, "false") {
			user.Disabled = true
		}
		if user.Shell == "" {
			user.Disabled = true
		}

		// Add user to array.
		u.Users = append(u.Users, user)
	}
	return nil
}

// Find user info for ID.
func (u *UNIXAccounts) userWithID(id uint64) *User {
	for _, user := range u.Users {
		if user.ID == id {
			return user
		}
	}
	return nil
}

// Find user info for name.
func (u *UNIXAccounts) userWithName(name string) *User {
	for _, user := range u.Users {
		if user.Name == name {
			return user
		}
	}
	return nil
}

// Find group info for ID.
func (u *UNIXAccounts) groupWithID(id uint64) *Group {
	for _, group := range u.Groups {
		if group.ID == id {
			return group
		}
	}
	return nil
}

// Find group info for name.
func (u *UNIXAccounts) groupWithName(name string) *Group {
	for _, group := range u.Groups {
		if group.Name == name {
			return group
		}
	}
	return nil
}

// Get all user accounts which are members of a group.
func (u *UNIXAccounts) usersInGroup(group *Group) []*User {
	var users []*User
	// Users with the Group ID set to the group's ID are a member.
	for _, user := range u.Users {
		if user.GID == group.ID {
			users = append(users, user)
		}
	}
	// Find user info for each member.
	for _, name := range group.Users {
		user := u.userWithName(name)
		if user == nil {
			continue
		}
		// If the member was added previously, we do not want duplicates.
		alreadyExists := false
		for _, usr := range users {
			if usr == user {
				alreadyExists = true
				break
			}
		}
		if !alreadyExists {
			// The member is not a duplicate, so we add it to the array.
			users = append(users, user)
		}
	}
	return users
}

// The sign command calls this function.
func sign(c *cli.Context) error {
	// Load the configuration.
	config := initConfig(c)
	environmentFilter := c.String("environment")

	// Get all UNIX Accounts.
	accounts := new(UNIXAccounts)
	err := accounts.init()
	if err != nil {
		return err
	}

	// Go through the environments.
	for _, environment := range config.Evironments {
		// If we are filtering to a sepcific environment, ones which are not that environment should be skipped.
		if environmentFilter != "" && environmentFilter != environment.Name {
			continue
		}
		// If the system group is not set or if this is not setup to sign user keys, we ignore this environment.
		if environment.SystemGroup == "" || !environment.UserKey {
			continue
		}

		fmt.Println("Signing keys for environment", environment.Name)

		// Get the group for the environment from the UNIX Accounts.
		group := accounts.groupWithName(environment.SystemGroup)
		if group == nil {
			continue
		}

		// Find all members of the group and loop to sign a key for each member.
		users := accounts.usersInGroup(group)
		for _, user := range users {
			// If the user is disabled, we need to ignore.
			if user.Disabled {
				continue
			}
			// If the user does not already have an .ssh directory... We will ignore it.
			if _, err := os.Stat(user.HomeDir + "/.ssh"); err != nil {
				continue
			}

			// Get the path for the user key.
			userPrivKey := user.HomeDir + "/.ssh/id_cert_" + environment.Name
			userPubKey := userPrivKey + ".pub"

			// If the user key was not generated, we need to make a new key.
			if _, err := os.Stat(userPrivKey); err != nil {
				// Make a key using our default type.
				pub, priv, err := keys.GenerateKeyPair(config.KeyDefaults.Type, config.KeyDefaults.Curve, config.KeyDefaults.Size)
				if err != nil {
					return err
				}
				// If we cannot sign with the key, something is wrong.
				if _, ok := priv.(crypto.Signer); !ok {
					return errors.Errorf("key of type %T is not a crypto.Signer", priv)
				}
				// Get the public key in a form that we can generate an authorized key file.
				sshKey, err := ssh.NewPublicKey(pub)
				if err != nil {
					return errors.Wrapf(err, "error converting public key")
				}
				// Get the private key in a format which can be saved to disk.
				p, err := pemutil.Serialize(priv, pemutil.WithOpenSSH(true))
				if err != nil {
					return err
				}
				privKeyB := pem.EncodeToMemory(p)

				// Prepare the authorized key.
				pubKeyB := ssh.MarshalAuthorizedKey(sshKey)

				// Save the private key.
				f, err := os.Create(userPrivKey)
				if err != nil {
					return err
				}
				f.Write(privKeyB)
				f.Close()
				os.Chmod(userPrivKey, 0600)
				os.Chown(userPrivKey, int(user.ID), int(user.GID))

				// Save the public key.
				f, err = os.Create(userPubKey)
				if err != nil {
					return err
				}
				f.Write(pubKeyB)
				f.Close()
				os.Chmod(userPubKey, 0600)
				os.Chown(userPubKey, int(user.ID), int(user.GID))
			}

			// Read the environment's private key.
			privKeyFile, err := ioutil.ReadFile(environment.CAKeyFile)
			if err != nil {
				return errors.Errorf("Unable to read private key: %v", err)
			}

			// Create the Signer for this private key.
			authority, err := ssh.ParsePrivateKey(privKeyFile)
			if err != nil {
				return errors.Errorf("Unable to read private key: %v", err)
			}

			// Read the user's public key.
			pubKeyFile, err := ioutil.ReadFile(userPubKey)
			if err != nil {
				return errors.Errorf("Unable to read public key: %v", err)
			}

			// Read the provided public key.
			pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(pubKeyFile)
			if err != nil {
				return errors.Errorf("Unable to read public key: %v", err)
			}
			if len(rest) > 0 {
				return errors.Errorf("rest: got %q, want empty", rest)
			}

			// Current time used for validation date range.
			now := time.Now()

			// The key ID can have a place holder for the username.
			keyID := environment.SignOptions.KeyID
			keyID = strings.Replace(keyID, "USERNAME", user.Name, 10)

			// Create certificate.
			cert := &ssh.Certificate{
				Key:             pubKey,
				Serial:          0,
				CertType:        ssh.UserCert,
				KeyId:           keyID,
				ValidPrincipals: environment.SignOptions.ValidPrincipals,
				ValidAfter:      uint64(now.Add(-10 * time.Minute).Unix()),
				ValidBefore:     uint64(now.Add(time.Second * environment.SignOptions.Duration).Unix()),
				Permissions: ssh.Permissions{
					CriticalOptions: environment.SignOptions.Options,
					Extensions:      environment.SignOptions.Extensions,
				},
			}

			// Sign the certificate.
			cert.SignCert(rand.Reader, authority)

			// Get the signed certificate in an authorized key format.
			data := ssh.MarshalAuthorizedKey(cert)

			// Save the certificate to disk.
			certPath := userPrivKey + "-cert.pub"
			f, err := os.Create(certPath)
			if err != nil {
				return err
			}
			f.Write(data)
			f.Close()
			os.Chmod(certPath, 0600)
			os.Chown(certPath, int(user.ID), int(user.GID))

			fmt.Println("Signed key for", user.Name)
		}
	}

	return nil
}
