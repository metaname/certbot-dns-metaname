# certbot-dns-metaname

Requires: Python 3.6 or newer, certbot 0.31.0 or newer

This plugin for [certbot](https://certbot.eff.org/) enables you to complete `dns-01` ACME challenges with DNS zones hosted by [Metaname](https://metaname.net/).

You'll need a Metaname account and API token to use this plugin.

## Installation

A `.deb` package is available from https://github.com/metaname/certbot-dns-metaname/releases for Debian or Ubuntu system that have `certbot` installed via `apt`.

Alternatively, using Python packaging tools:

```console
# pip install certbot-dns-metaname
```

Once the plugin is installed, create a file to store your Metaname credentials in. These credentials are available from https://metaname.net/my/settings while signed in to a Metaname account.

Make sure the file you create is only readable by the user you run `certbot` as. Usually this is `root`. Protect these credentials the same as you would protect your Metaname account password.

```console
# touch /etc/metaname.ini && chmod 0600 /etc/metaname.ini
# editor /etc/metaname.ini
```

Add two lines to the file specifying your Metaname account reference and API key:

```ini
dns_metaname_account_reference = <insert your 4 character Metaname account reference here>
dns_metaname_api_key = <insert your 48 character Metaname API key here>
```

For older versions of certbot you may need to prefix each line with `certbot_dns_metaname:`.

## Usage

The first time you use the `dns-metaname` plugin it will ask you for the path to your `metaname.ini` credentials file. To prevent this interactive prompt, add the `--metaname-dns-credentials` option to your invocations of `certbot`, passing it the path to `metaname.ini`.

For instance, if you have `example.com` configured for DNS hosting in your Metaname account, a certificate for `www.example.com` can be requested from Let's Encrypt with `certbot`:

```console
# certbot certonly --authenticator dns-metaname -d www.example.com
```

For older versions of `certbot` you may need to prefix `dns-metaname` with `certbot-dns-metaname:`, for instance:

```console
# certbot certonly --authenticator certbot-dns-metaname:dns-metaname -d www.example.com
```
