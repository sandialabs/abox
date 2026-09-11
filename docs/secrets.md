# Secret injection

abox can hold API keys **on the host** and inject them into the agent's outbound
requests, so the untrusted agent inside the VM can *use* a credential without ever
*holding* it. This is implemented in the per-instance HTTP proxy: for a configured
host, the proxy sets an auth header (e.g. `x-api-key`) on the way out.

## How it works

```
abox.yaml  http.secret_injections:
  [{key: anthropic, host: api.anthropic.com, header: x-api-key, path_prefix: /v1/}]
                     │  (non-sensitive mapping, safe to commit)
host store   secrets file:  anthropic = <value>   (0600, under the instance dir, never in the VM)
                     │
abox start → HTTP filter loads the mapping + value, then:
                     │
VM agent:  curl https://api.anthropic.com/v1/messages   (no key)
                     │  CONNECT → TLS MITM intercept
proxy sets  x-api-key: <value>  → forwards upstream
```

The value lives only in the per-instance store on the host
(`~/.local/share/abox/instances/<name>/secrets`, mode `0600`). It is never written
to the cloud-init ISO, the overlay, or the guest filesystem.

## Usage

1. Declare the binding in `abox.yaml` (the non-sensitive part — no value here):

   ```yaml
   http:
     secret_injections:
       - key: anthropic
         host: api.anthropic.com
         header: x-api-key
         path_prefix: /v1/        # optional; only inject on these paths
         # value_prefix: "Bearer " # optional; e.g. for Authorization headers
   ```

2. Create the instance and store the value on the host:

   ```bash
   abox create dev --from-file abox.yaml
   abox secrets set dev anthropic --from-file ./key.txt
   # or:  abox secrets set dev anthropic --from-env ANTHROPIC_API_KEY
   ```

3. Start the instance. The agent can now call the API with no key of its own:

   ```bash
   abox start dev
   abox ssh dev
   # inside the VM:
   curl -s https://api.anthropic.com/v1/models   # authenticated by the proxy
   env | grep -i anthropic                        # nothing — the key isn't in the guest
   ```

### Managing values

```bash
abox secrets set dev <key> --from-file PATH   # preferred
abox secrets set dev <key> --stdin            # e.g. printf %s "$KEY" | abox secrets set ...
abox secrets set dev <key> --from-env NAME    # convenient, but see the note below
abox secrets list dev                          # key names only, never values
abox secrets remove dev <key>
```

The value is never accepted as a command-line argument (that would leak it into
shell history and the process table). `--from-file` and `--stdin` are preferred;
`--from-env` exposes the value in the `abox secrets set` process environment for
the duration of the command.

## Security model

**What this guarantees:** the agent never holds the key at rest. The value stays on
the host; only the resolved header is added to requests the proxy forwards.

**The one limitation you must understand — header reflection.** Injection is keyed
on the *host*, but the agent controls the request path and body. If the bound host
exposes any reachable endpoint that echoes request headers back (a debug/echo/trace
endpoint, some GraphQL servers, an error page that dumps headers, a webhook-test
endpoint), the agent can read the injected key out of the response. Single-purpose
APIs like `api.anthropic.com` generally don't do this, but the feature is generic.

`path_prefix` is the mitigation: restrict injection to the specific API paths the
agent needs, so a reflecting endpoint elsewhere on the host never sees the header.
Set it as narrowly as the API allows. Note that reflection can still be probed
*within* the allowed prefix (e.g. via `/./` or `;`-parameters that normalize into
it), so scope the prefix to the exact path the agent needs and prefer a path with
no reflecting sibling. Injection is also suppressed on `TRACE` requests (which echo
the request verbatim), removing that guaranteed-reflection method.

**Vectors that are already closed** by the proxy's design:

- **Domain fronting / `Host`-spoofing:** injection keys off the CONNECT target host,
  which the guest cannot spoof via the inner `Host:` header or an absolute request
  URI. Forward-proxy absolute-URI requests (no CONNECT) are never injected.
- **Plaintext leak:** injection only happens on MITM-intercepted HTTPS requests.
  A secret is never added to a plaintext `http://` request.
- **Path traversal of `path_prefix`:** requests with `..` or percent-encoded path
  separators are normalized/rejected before the prefix check, so `/v1/../debug`
  cannot slip past a `/v1/` prefix.
- **DNS rebinding / impersonation:** the post-resolution SSRF gate aborts the dial
  for a bound host that resolves to a private/loopback/metadata address. For a bound
  host rebound to a *public* attacker IP, the proxy still verifies the upstream TLS
  certificate against the bound hostname (system roots, no `InsecureSkipVerify`), so
  the handshake fails and the secret is never sent to an impersonator.
- **`TRACE` reflection:** injection is skipped on `TRACE`, which would otherwise echo
  the injected header straight back to the guest.

**Fail-closed behavior:**

- Injection requires `http.mitm: true`; it is refused at startup otherwise.
- Injection is refused in passive (profiling) mode — both at startup and if the mode
  is toggled to passive at runtime.
- If a binding's `key` has no stored value, the proxy **strips** that header from the
  request instead of forwarding whatever the guest supplied — the agent can never
  provide its own credential to a bound host. Strip also fires when the request path
  can't be safely normalized, so an encoded path can't dodge it.

**At rest:** the store file is plaintext at mode `0600`, the same trust level as the
instance's SSH private key and MITM CA key. Encryption at rest (OS keychain / age)
is not yet implemented.

## Operational notes

- **Changing a binding** (the `secret_injections` block) after `abox create` has no
  effect on a created instance — there is no `abox update`. Re-create the instance or
  hand-edit its `config.yaml`.
- **Changing a value** requires `abox stop` then `abox start`: a plain re-`start`
  does not restart an already-running HTTP filter, so it would keep the old value.
  Likewise, `abox secrets remove` does not take effect on a running instance until
  the HTTP filter restarts.
- **Upstream proxy:** if `http_proxy`/`https_proxy` is set for the HTTP filter, the
  dial-time SSRF/rebinding gate can't vet the proxied leg's real target (the proxy
  resolves it). The upstream TLS cert check still binds the secret to the intended
  host, but the filter logs a warning; avoid combining an upstream proxy with secret
  injection unless the proxy is trusted.
- **`abox export` / `abox import`** do **not** preserve secret injections. The export
  manifest carries only a minimal instance (name, CPUs, memory, base, disk), so an
  imported instance has no `secret_injections` bindings and no stored values —
  re-declare the bindings (via `--from-file abox.yaml` on import, or by editing
  `config.yaml`) and repopulate values with `abox secrets set`. (This is the same
  limitation that applies to other `http.*` settings today.)

## Audit

Applying injections emits one audit record per binding (`action=secret.inject`) with
the instance, host, key name, and header — never the value. `abox secrets set` and
`abox secrets remove` audit the key name only. See
[docs/troubleshooting.md](troubleshooting.md#log-locations) for audit log locations.
