# Secret Agent (`secreta`)

Secret agent is a local macOS daemon that brokers secret creation and access over a Unix domain socket. It acts as an intermediary between other applications and keychain stored secrets and providing the following features:

* Per application access control.
* Usable from both signed and unsigned applications. 
* Allows biometric authorization.
* Configurable access cache time - "re-prompt after X seconds"
* An audit log of all accesses by what application to each secret.

## Design

The agent runs as a background process that owns all keychain interactions. Clients connect over a Unix domain socket using a length-prefixed JSON protocol. The agent identifies callers by CDHash and uses the binary name and path for user-facing context. All access attempts emit audit notifications. Secrets are never stored in memory in the agent, they are retrieved from keychain on ever access.

App identity is rooted in the caller's CDHash, while user-facing prompts and audit records include the binary name and path so humans can recognize the source. This mapping is part of the policy metadata used to determine per-app access behavior.

The design works with either legacy keychain items or the data protection keychain, since the agent always owns the keychain operations. The current implementation uses legacy keychain items for simplicity, but the same flow applies if the storage backend changes.

Authentication prompts shown to the user are local authentication challenges from the agent, not keychain prompts. This means the security model relies on the integrity of the agent binary itself and the keychain ACL only permitting that binary; if the agent identity changes, it would need to re-authenticate to access existing secrets.

The primary API paths are available:

1. Create a secret: The client supplies a secret name and value, plus an optional cache TTL. The agent stores the secret in the keychain using the naming pattern `sm:<name>` and records metadata including the cache TTL. A cache TTL of `0` means every access requires a fresh authorization; otherwise, access is cached in memory per app until the TTL expires.
2. Access a secret: The client requests a named secret. The agent checks per-app policy and in-memory cache to determine if a local authentication challenge is required. If needed, the agent prompts with app and secret context before returning the secret. Every access attempt emits an audit notification regardless of whether a prompt was shown.
3. Delete a secret: The client requests removal of a named secret. The agent clears policy metadata and in-memory cache, deletes the keychain item, and emits an audit event describing the outcome.

## Installation

Build and install a user-level launch agent with the provided scripts. This installs the release binary into `~/.local/bin` by default and registers a LaunchAgent under `~/Library/LaunchAgents` so the daemon starts at login.

The install script has the following effects on your machine:

- Installs the `secreta` binary into `~/.local/bin` (or the `INSTALL_DIR` override).
- Registers `com.secreta.agent` under `~/Library/LaunchAgents` for auto-start.
- Removes any stale `/tmp/secreta.sock` and restarts the agent to recreate it.

```bash
./scripts/install.sh
```

You can uninstall and remove the LaunchAgent with:

```bash
./scripts/uninstall.sh
```

If you need custom paths, set `INSTALL_DIR` and/or `LAUNCH_AGENTS_DIR` when running the scripts.

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
- `delete` requires `--name`
- `status` checks the socket health

## SDK

### Go

Install the Go module from this repo and use the client helper to call the socket API:

```bash
go get github.com/jptrs93/secreta/sdk/go/secretadapter
```

```go
package main

import (
    "fmt"
    "github.com/jptrs93/secreta/sdk/go/secretadapter"
)

func main() {
    client := secretadapter.NewClient()
    response, err := client.FetchSecret("demo", "testing")
    if err != nil {
        panic(err)
    }
    fmt.Println(response.SecretValue)
}
```
