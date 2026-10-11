# Device-start trusted ingress signer

`device-start.mjs` is a small Node 24 sidecar for the unauthenticated device-code
bootstrap route. It listens on loopback (default `127.0.0.1:8191`), accepts only
`POST` and browser `OPTIONS` for the exact `/functions/v1/device-start` path,
limits request headers to 8 KiB and request bodies to 4 KiB, and forwards to one
fixed upstream URL. It rejects upstream redirects and responses over 16 KiB.

The signer **does not use** `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`,
`Host` or any client-supplied `x-aidr-client-*` value. It accepts a canonical
client IP only from `X-AIDR-Proxy-Client-IP` after verifying both the connecting
peer's exact IP and `X-AIDR-Proxy-Token`. It then sends the three signed headers
that `supabase/functions/device-start/index.ts` verifies:

```
x-aidr-client-ip: <canonical IPv4 or IPv6>
x-aidr-client-timestamp: <Unix seconds>
x-aidr-client-signature: hex(HMAC-SHA256(secret, "device-start:v1\n<timestamp>\n<ip>"))
```

The function permits 60 seconds of clock skew, so synchronize signer and
function clocks. The signer and function must share the same
`AIDR_DEVICE_START_INGRESS_SECRET` (at least 32 UTF-8 bytes). The proxy token is
a different 32-byte-or-longer secret shared only by Nginx and the signer. Keep
both out of browser builds, logs, public environment files and source control.
Nginx must set `X-AIDR-Proxy-Request-ID` to its per-request `$request_id`; the
signer rejects a repeated ID for 60 seconds. The replay cache is in-memory and
bounded, so a signer restart clears it; it supplements the loopback/token
boundary and is not protection for a compromised host or secret.

The prepared self-hosted deployment copies this directory to `ingress/` and
writes a private `.env.ingress` beside `compose.yml`. Run the prepared sidecar
from that deployment directory:

```
node --env-file=.env.ingress ingress/device-start.mjs
```

For an independently managed or cloud ingress, save these values from your
secret manager as `/etc/aidr/device-start-signer.env` on Linux. Restrict the
file to the signer service account; it is separate from the generated
deployment `.env.ingress` file:

```
AIDR_DEVICE_START_INGRESS_SECRET=<shared-with-device-start-function>
AIDR_DEVICE_START_PROXY_TOKEN=<shared-with-TLS-reverse-proxy>
AIDR_DEVICE_START_UPSTREAM_URL=http://127.0.0.1:8000/functions/v1/device-start
AIDR_DEVICE_START_TRUSTED_PEERS=127.0.0.1
AIDR_DEVICE_START_LISTEN_HOST=127.0.0.1
AIDR_DEVICE_START_LISTEN_PORT=8191
```

Set `AIDR_DEVICE_START_INGRESS_SECRET` in the Edge Function environment too,
then restart/redeploy the function. For cloud mode, set
`AIDR_DEVICE_START_ANON_KEY` in the signer environment to the selected project's
public anonymous gateway key; preparation leaves it unset, and the deployment
doctor fails its cloud preflight until it matches `ANON_KEY` in `.env`. The
signer injects that key and ignores caller Authorization and `apikey` headers.
The upstream may be a fixed HTTPS URL in cloud mode. Plain HTTP is accepted only
for numeric loopback upstreams. An HTTPS upstream uses Node's standard
certificate verification; this sidecar does not create a cloud project or
provision its TLS/certificate trust.

For a manual Linux check from the repository root, use that same private file:

```
node --env-file=/etc/aidr/device-start-signer.env deploy/ingress/device-start.mjs
```

For a Linux service, adapt `aidr-device-start.service.reference`, create the
restricted `aidr` account, place its private environment at
`/etc/aidr/device-start-signer.env`, and enable the unit under systemd. On
Windows, use a customer-approved service supervisor with the same loopback and
private environment settings. A shell launched manually is a test process, not
an availability setup.

On the TLS host, adapt `nginx.device-start.reference.conf`, substitute the
**same** proxy token, and validate it with `nginx -t` before reload. Keep the
signer and Nginx on the same trusted host; restrict local process access and
the private Nginx configuration. Loopback plus a token does not provide a
security boundary against a fully compromised host or an operator who can read
both secrets. Never publish port 8191. Restrict direct API port 8000 to loopback
or a private network; direct unsigned device-start calls fail at the function.
The reference claims the 80/443 default-server slots and rejects other Host
values; if integrating into an existing Nginx instance, preserve an equivalent
default-deny host route rather than dropping the `default_server`/Host checks.
Nginx's `$remote_addr` is the directly connected TCP/TLS peer. If a CDN or load
balancer sits in front, it will be the bucketed peer until the operator
explicitly configures trusted hop addresses and validates forwarding; do not
simply substitute a client-provided forwarding header. See the
[Nginx proxy header directives](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
for the header replacement behavior used by the reference config.

## Public TLS renewal

`aidr-tls-renew.service`, `aidr-tls-renew.timer` and the renewal script are
prepared in `/srv/aidr/ingress/`. They are not installed or enabled. The unit
uses that exact path; adapt it if the prepared deployment lives elsewhere.
The reference Nginx configuration serves HTTP-01 challenges from
`/var/www/aidr-acme` on port 80 and presents Certbot's native
`/etc/letsencrypt/live/<hostname>/` certificate on port 443. For a first
certificate, before starting the TLS Nginx configuration, verify DNS and port
80 reachability and issue it with Certbot's standalone authenticator while
port 80 is free. Then install/test/start the adapted Nginx configuration. The
timer uses the same Certbot lineage with the webroot authenticator thereafter.
Do not try to start Nginx with a certificate path that does not exist yet.
For the reference hostname (replace it, and the email, with values you control):

```sh
sudo install -d -m 0755 /var/www/aidr-acme /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt
sudo certbot certonly --standalone --non-interactive --agree-tos --config-dir /etc/letsencrypt --cert-name api.aidr.customer.example -d api.aidr.customer.example -m tls-owner@customer.example
```

Install the adapted Nginx reference only after this command succeeds. Check
`nginx -t`, start Nginx, and fetch an HTTP-01 test file through the public
hostname before enabling the webroot renewal timer. Run
`sudo certbot renew --cert-name api.aidr.customer.example --webroot-path
/var/www/aidr-acme --dry-run` to exercise renewal against the staging ACME
service; this does not replace a later real renewal receipt. A DNS record, port 80 and
certificate authority access are required on the real host; this repository
does not provide them.

On the TLS host, create `/etc/aidr/tls-renew.env` privately with
`AIDR_TLS_HOSTNAME`, `AIDR_TLS_EMAIL` and optionally `AIDR_TLS_DIR` (Certbot
configuration root, default `/etc/letsencrypt`), `AIDR_TLS_WEBROOT` (default
`/var/www/aidr-acme`), `AIDR_TLS_RECEIPT` (default
`/var/lib/aidr/tls-renewal-receipt.json`), `AIDR_ACME_CLIENT` (default
`certbot`) and `AIDR_NGINX` (default `nginx`). If any path changes, update the
Nginx reference and the unit's writable paths together. Install the prepared
units before enabling them:

```sh
sudo install -m 0644 /srv/aidr/ingress/aidr-tls-renew.service /etc/systemd/system/aidr-tls-renew.service
sudo install -m 0644 /srv/aidr/ingress/aidr-tls-renew.timer /etc/systemd/system/aidr-tls-renew.timer
sudo systemctl daemon-reload
sudo systemctl enable --now aidr-tls-renew.timer
sudo systemctl start aidr-tls-renew.service
```

`scripts/deployment-tls-renew.mjs` drives the ACME client
(`certbot certonly --keep-until-expiring --config-dir <AIDR_TLS_DIR> --cert-name
<AIDR_TLS_HOSTNAME> --webroot
-w <AIDR_TLS_WEBROOT>`), and
touches Nginx only after the challenge succeeded and the served chain file was
inspected: the file must carry a leaf plus its issuer, the leaf must have been
issued by that issuer, it must cover the requested hostname, its validity window
must contain the current time, `nginx -t` must pass and the reload command must
succeed. Every attempt writes the private renewal receipt under
`/var/lib/aidr` by default, with the timestamp, hostname, ACME client, SHA-256 certificate
fingerprint, expiry, whether the challenge succeeded, whether the ingress was
reloaded and the outcome. A missing ACME client, an incomplete chain, a chain for
another hostname and a failed challenge all leave `reloaded: false`, write a
`refused` or `failed` receipt and exit non-zero instead of reporting success. A
certificate the client reports as not due is recorded as `unchanged` and the
ingress is not reloaded.

Keep the certificate paths in `nginx.device-start.reference.conf` pointed at the
same Certbot lineage this unit renews, and actually probe the HTTP-01 webroot
from outside before relying on the timer. A receipt is a local attempt record: it is
not proof that a certificate authority issued a certificate for a public
hostname, and the tests for this unit inject a command runner with fixture chain
files, so no real ACME challenge, domain, certificate authority or certificate
was exercised in this repository.

## On-prem ingress with customer-supplied certificates

`nginx.onprem.reference.conf` is the reference for on-prem and air-gapped hosts:
one vhost for the dashboard (`127.0.0.1:8080`) and one for the API gateway
(`127.0.0.1:8000`, including the device-start signer route above), HSTS,
`nosniff`, `Referrer-Policy` and related headers on both, TLS 1.2/1.3 only, no
public `/metrics`, an API vhost that proxies only the Supabase API prefixes
(`/auth/v1/`, `/rest/v1/`, `/storage/v1/`, `/functions/v1/`, `/realtime/v1/`,
`/graphql/v1`, `/pg/`, `/.well-known/oauth-authorization-server`) and answers
everything else with `404`, so Supabase Studio is never served from the API host
(operators reach it on the loopback-only `127.0.0.1:8001` listener over an SSH
tunnel; see "Supabase Studio (operator-only)" in [the on-prem guide](../onprem/README.md)),
and a default server that drops unknown hostnames
(`ssl_reject_handshake`, nginx 1.19.4 or newer). Certificates come from the
customer's CA and are read from `/etc/aidr/tls/live/<host>/{fullchain,privkey}.pem`.

Install or rotate a certificate with the static mode of the same script:

```sh
sudo node /srv/aidr/ingress/deployment-tls-renew.mjs --mode static \
  --hostname api.aidr.customer.example \
  --cert-file /secure-delivery/api-fullchain.pem --key-file /secure-delivery/api-key.pem \
  [--tls-dir /etc/aidr/tls] [--min-days 14] [--receipt /var/lib/aidr/tls-renewal-receipt.json]
```

Before anything is written it requires a leaf plus its issuer, a leaf that
covers the hostname and is currently valid with at least `--min-days` remaining,
and a private key that belongs to the leaf and is owner-only (mode 0600). It then
installs both files atomically (key 0600), runs `nginx -t` and reloads nginx; a
failed test or reload restores the previously installed pair. An identical pair
is recorded as `unchanged` without a reload. Every attempt writes the same kind
of receipt as ACME mode with `mode: "static"` and `key_matches_certificate`.
Static mode does not renew anything: schedule the replacement before
`certificate_expires_at`, and confirm from a client that trusts the customer CA.
The contract tests (`node --test scripts/deployment-tls-renew.test.mjs`) mint
throwaway Ed25519 chains in memory; they do not run a real nginx.

Run the local contract tests with:

```
node --test deploy/ingress/device-start.test.mjs
```

These tests exercise a loopback signer and fake API, including forged headers,
untrusted peer/token, duplicated proxy IP, body limits, IPv6 normalization,
preflight and redirects. They are not evidence that a customer's TLS, routing,
secret custody, clock synchronization or cloud ingress is correctly installed;
verify those on the actual deployment before field acceptance.
