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

The prepared self-hosted deployment copies this directory to `ingress/` and
writes a private `.env.ingress` beside `compose.yml`. Run the prepared sidecar
from that deployment directory:

```
node --env-file=.env.ingress ingress/device-start.mjs
```

For an independent/cloud ingress, create a private signer environment file
with these keys, using values from your secret manager:

```
AIDR_DEVICE_START_INGRESS_SECRET=<shared-with-device-start-function>
AIDR_DEVICE_START_PROXY_TOKEN=<shared-with-TLS-reverse-proxy>
AIDR_DEVICE_START_UPSTREAM_URL=http://127.0.0.1:8000/functions/v1/device-start
AIDR_DEVICE_START_TRUSTED_PEERS=127.0.0.1
AIDR_DEVICE_START_LISTEN_HOST=127.0.0.1
AIDR_DEVICE_START_LISTEN_PORT=8191
```

Set `AIDR_DEVICE_START_INGRESS_SECRET` in the Edge Function environment too,
then restart/redeploy the function. If a managed Supabase upstream requires its
public anonymous gateway key, set `AIDR_DEVICE_START_ANON_KEY` in the signer
environment; the signer injects that key and ignores caller Authorization and
`apikey` headers. The upstream may be a fixed HTTPS URL in cloud mode. Plain
HTTP is accepted only for numeric loopback upstreams. An HTTPS upstream uses
Node's standard certificate verification; this sidecar does not create a cloud
project or provision its TLS/certificate trust.

An independent launch from the repository root after preparing that private
environment file is:

```
node --env-file=.aidr-deploy/.env.device-start-signer deploy/ingress/device-start.mjs
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
Nginx's `$remote_addr` is the directly connected TCP/TLS peer. If a CDN or load
balancer sits in front, it will be the bucketed peer until the operator
explicitly configures trusted hop addresses and validates forwarding; do not
simply substitute a client-provided forwarding header. See the
[Nginx proxy header directives](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
for the header replacement behavior used by the reference config.

## Public TLS renewal

`aidr-tls-renew.service` and `aidr-tls-renew.timer` are a reference systemd pair
prepared beside this signer into the deployment directory (`ingress/`). Preparing
them does not install, enable or run them, and the doctor only asserts that both
files are present. On the TLS host, place the private environment file at
`/etc/aidr/tls-renew.env` with `AIDR_TLS_HOSTNAME`, `AIDR_TLS_EMAIL`,
`AIDR_TLS_DIR` (default `/etc/aidr/tls`), `AIDR_TLS_WEBROOT` (the HTTP-01 webroot
Nginx serves), `AIDR_TLS_RECEIPT`, `AIDR_ACME_CLIENT` (default `certbot`) and
`AIDR_NGINX`, then enable the timer:

```
systemctl enable --now aidr-tls-renew.timer
```

`scripts/deployment-tls-renew.mjs` drives the ACME client
(`certbot certonly --keep-until-expiring --webroot -w <AIDR_TLS_WEBROOT>`), and
touches Nginx only after the challenge succeeded and the served chain file was
inspected: the file must carry a leaf plus its issuer, the leaf must have been
issued by that issuer, it must cover the requested hostname, its validity window
must contain the current time, `nginx -t` must pass and the reload command must
succeed. Every attempt writes `renewal-receipt.json` next to the certificate
chain with the timestamp, hostname, ACME client, SHA-256 certificate
fingerprint, expiry, whether the challenge succeeded, whether the ingress was
reloaded and the outcome. A missing ACME client, an incomplete chain, a chain for
another hostname and a failed challenge all leave `reloaded: false`, write a
`refused` or `failed` receipt and exit non-zero instead of reporting success. A
certificate the client reports as not due is recorded as `unchanged` and the
ingress is not reloaded.

Keep the certificate paths in `nginx.device-start.reference.conf` pointed at the
same chain and key this unit renews. A receipt is a local attempt record: it is
not proof that a certificate authority issued a certificate for a public
hostname, and the tests for this unit inject a command runner with fixture chain
files, so no real ACME challenge, domain, certificate authority or certificate
was exercised in this repository.

Run the local contract tests with:

```
node --test deploy/ingress/device-start.test.mjs
```

These tests exercise a loopback signer and fake API, including forged headers,
untrusted peer/token, duplicated proxy IP, body limits, IPv6 normalization,
preflight and redirects. They are not evidence that a customer's TLS, routing,
secret custody, clock synchronization or cloud ingress is correctly installed;
verify those on the actual deployment before field acceptance.
