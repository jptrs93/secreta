# Secret Agent (`secreta`)

Secret agent is a local macOS daemon that brokers secret creation and access over a Unix domain socket. It acts as an intermediary between other applications and keychain stored secrets and providing the following features:

* Per application access control.
* Usable from both signed and unsigned applications. 
* Allows biometric authorization.
* Configurable access cache time - "re-prompt after X seconds"
* An audit log of all accesses by what application to each secret.

## Design

The agent runs as a background process that owns all keychain interactions. Clients connect over a Unix domain socket using a length-prefixed JSON protocol. The agent identifies callers by CDHash and uses the binary name and path for user-facing context. All access attempts emit audit notifications, and secrets are never logged in plaintext.

Two primary API paths are available:

1. Create a secret: The client supplies a secret name and value, plus an optional cache TTL. The agent stores the secret in the keychain using the naming pattern `sm:<cache_seconds>:<name>` and records policy metadata. A cache TTL of `0` means every access requires a fresh authorization; otherwise, access is cached in memory per app until the TTL expires.
2. Access a secret: The client requests a named secret. The agent checks per-app policy and in-memory cache to determine if a local authentication challenge is required. If needed, the agent prompts with app and secret context before returning the secret. Every access attempt emits an audit notification regardless of whether a prompt was shown.

## CLI


The `secreta` binary defaults to daemon mode. Use the `secret` subcommand for quick manual testing.

```bash
swift run secreta secret create --name demo --value test
swift run secreta secret fetch --name demo
```

Options:

- `--socket` override the Unix socket path (default: /tmp/secreta.sock)
- `--timeout` socket timeout in seconds
- `--cache-seconds` cache TTL for create
- `--reason` access reason for fetch
