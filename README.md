# SSH Certificate Authority Toolkit

This is a toolkit for configuring a SSH certificate authority, mainly designed with a jump box in mind with a setup similar to the following as an example.

On the jump box, we have 2 groups. `production` and `dev`, where the production team has access to production servers and the dev team has access to development servers. As the jump box is managed by a trusted party, we can setup a certificate authority which automatically creates and signs ssh keys to grant the users of each group access to the servers they need access to. As the jump box is also a certificate authority server, we are also able to sign host certificates for each server.

This allows for the following benefits.

1. Short lived certificates can be issued on a regular basis. In the default configuration, a certificate is issued for 1 hour. With a cron job setup to run every 30 minutes, all users gets updated certificates before they expire. This allows for user accounts to be deactivated without concern of a stolen ssh key possibly being able to access servers.

2. As all servers have a signed host key, time of first use (TOFU) warnings can be eliminated with all servers with a signed host key being trusted. Any server which throws a TOFU warning can be treated as suspicious or potentially compromised.

## Example configuration

On the jump box, create the `/etc/ssh-ca/` directory and place a copy of the example configuration `config.json` in etc (change parameters as needed).

Create the certificate authority keys for product, dev, and server host key signing.

```bash
ssh-keygen -t ed25519 -N '' -C ca_production@example.com -f /etc/ssh-ca/ssh_ca_production
chmod 600 /etc/ssh-ca/ssh_ca_production
ssh-keygen -t ed25519 -N '' -C ca_dev@example.com -f /etc/ssh-ca/ssh_ca_dev
chmod 600 /etc/ssh-ca/ssh_ca_dev
ssh-keygen -t ed25519 -N '' -C ca_server@example.com -f /etc/ssh-ca/ssh_ca_server
chmod 600 /etc/ssh-ca/ssh_ca_server
```

Create a cron job to sign user certificates on the jump box.
```
@reboot /usr/local/bin/ssh-cert sign >/dev/null 2>&1
*/30 * * * * /usr/local/bin/ssh-cert sign >/dev/null 2>&1
```

Run the command after setup to generate and signed keys for each user in the account groups defined in the configuration file.

On the jump box, install the ssh-cert service by copying the ssh-cert.service file from the etc directory to /etc/systend/system/. Enable/start as follows.
```bash
systemctl enable ssh-cert.service
systemctl start ssh-cert.service
```

On all servers, create the `/etc/ssh-ca/` directory and copy the example config `client.json` (change parameters as needed).

Create a cron job to sign the host certificates. You can randomize the hour/minute to have servers request for certificates at different time frames to minimize load.
```
@reboot /usr/local/bin/ssh-host-client sign >/dev/null 2>&1
0 0 1 * * /usr/local/bin/ssh-host-client sign >/dev/null 2>&1
```

Run the sign command after setup to ensure that the servers get a signed certificate.

Create a global `known_hosts` file that sets the certificate as a known host for all accounts.

```bash
echo -n "@cert-authority * " > /etc/ssh/ssh_known_hosts
cat /etc/ssh-ca/ssh_ca_server.pub >> /etc/ssh/ssh_known_hosts
```

You can either distribute this `known_hosts` file to each user account, or you can leave it in the global `known_hosts` file and remove the existing known hosts files from each account to remove old signatures from accounts.

```bash
find /home/ -name known_hosts -print -delete
```

With the signed ssh keys being named different from the default names, we need to configure the global ssh_config file to include the identity. Edit `/etc/ssh/ssh_config` and, under the `Host *` host match, add the following.

```
  IdentityFile ~/.ssh/id_cert_production
  IdentityFile ~/.ssh/id_cert_dev
  IdentityFile ~/.ssh/id_ed25519
  IdentityFile ~/.ssh/id_rsa
```

On each server, setup a `TrustedUserCAKeys` in the `/etc/ssh/sshd_config` configuration like the following.

```
  TrustedUserCAKeys /etc/ssh/trusted-keys
```

In the `/etc/ssh/trusted-keys` file, put the public key(s) for the environment(s) this server allows connections. Example:

```
ssh-ed25519 AAAAC3AzaI1lDDI1NTE5AAAAICyHsn8hRNxbCh7FnX1EbwCDSSI+WT6CHHcPpSAMb6Gs ca_production@example.com
```

And with that change, your environment is now configured.

# Adding a new user account

Now that you have a configuration with this, you can easily add a user account that will receive a key. For an example, adding a user account for `john`.

```bash
USER=john
useradd $USER
usermod -a -G production $USER
mkdir /home/$USER/.ssh/; chown $USER: /home/$USER/.ssh/
/usr/local/bin/ssh-cert sign
```

You do not have to run the last line if you prefer to wait for the cron job to run.

# Special Notes

I highly recommend that you have Nginx/Caddy in-front of the signing server to add SSL and also all for more filtering. The signing server does not have SSL support by default, and while you must have the private keys for the returned certificates to be useful. Better safe than sorry. I have support for `X-Forwarded-For` which can be a security risk if someone knew a range you have authorized in the configuration.

Example Nginx configuration.
```nginx
server {
    listen       80;
    listen       [::]:80;
    server_name  ssh-ca.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen       443 ssl;
    listen       [::]:443 ssl;
    server_name  ssh-ca.example.com;

    ssl_certificate /etc/letsencrypt/live/ssh-ca.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ssh-ca.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;# Requires nginx >= 1.13.0 else use TLSv1.2
    ssl_prefer_server_ciphers on;
    ssl_dhparam /etc/nginx/dhparam.pem; # openssl dhparam -out /etc/nginx/dhparam.pem 4096
    ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH:ECDHE-RSA-AES128-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA128:DHE-RSA-AES128-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA128:ECDHE-RSA-AES128-SHA384:ECDHE-RSA-AES128-SHA128:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA384:AES128-GCM-SHA128:AES128-SHA128:AES128-SHA128:AES128-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
    ssl_ecdh_curve secp384r1; # Requires nginx >= 1.1.0
    ssl_session_timeout  10m;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off; # Requires nginx >= 1.5.9
    ssl_stapling on; # Requires nginx >= 1.3.7
    ssl_stapling_verify on; # Requires nginx => 1.3.7
    resolver 8.8.4.4 8.8.8.8 valid=300s;
    resolver_timeout 5s;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    access_log /dev/null;
    error_log /dev/null;

    location / {
        proxy_pass              http://127.0.0.1:7789;
        proxy_set_header        Host                 $host;
        proxy_set_header        X-Real-IP            $remote_addr;
        proxy_set_header        X-Forwarded-For      $proxy_add_x_forwarded_for;
        proxy_set_header        X-Remote-Port        $remote_port;
        proxy_set_header        X-Forwarded-Proto    $scheme;
        proxy_redirect          off;
    }
}
```
