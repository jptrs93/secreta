# Secret Agent (`secreta`)

Secret agent is a local macOS daemon that brokers secret creation and access over a Unix domain socket. It acts as an intermediary between other applications and keychain stored secrets providing the following features:

* Per application access control.
* Usable from both signed and unsigned applications. 
* Allows biometric authorization.
* Configurable access cache time - "re-prompt after X seconds"
* An audit log of all accesses by what application to each secret.

## Design

The agent runs as a background process that owns all keychain interactions. Clients connect over a Unix domain socket using a length-prefixed JSON protocol. All access attempts emit audit notifications and are logged. Secrets are never stored in memory in the agent, they are retrieved from keychain on every access.

Calling applications are identified by their CDHash where available. Otherwise, a combination of the path to their binary and hash of their binary is used.

The design would work ontop of either legacy keychain or the data protection keychain. The current implementation uses legacy keychain for simplicity.

Authentication prompts shown to the user are local authentication challenges from the agent, not keychain prompts. This means the security model relies on the integrity of the agent binary itself and the keychain ACL only permitting that binary; if the agent identity changes, it would need to re-authenticate to access existing secrets.

The primary API paths are available:

1. Create a secret: The client supplies a secret name and value, plus an optional cache TTL. The agent stores the secret in the keychain using the naming pattern `sm:<name>` and records metadata including the cache TTL. A cache TTL of `0` means every access requires a fresh authorization; otherwise, access is cached in memory per app until the TTL expires.
2. Access a secret: The client requests a named secret. The agent checks per-app policy and in-memory cache to determine if a local authentication challenge is required. If needed, the agent prompts with app and secret context before returning the secret. Every access attempt emits an audit notification regardless of whether a prompt was shown.
3. Delete a secret: The client requests removal of a named secret. The agent clears policy metadata and in-memory cache, deletes the keychain item, and emits an audit event describing the outcome.

## Installation

Build and install a user-level launch agent with the provided scripts. This installs the release binary into `~/.local/bin` by default, builds a daemon app bundle in `~/Applications/SecretaDaemon.app`, and registers a LaunchAgent under `~/Library/LaunchAgents` so the daemon starts at login.

The install script has the following effects on your machine:

- Installs the `secreta` CLI binary into `~/.local/bin` (or the `INSTALL_DIR` override).
- Builds and installs `SecretaDaemon.app` into `~/Applications` (or the `APP_INSTALL_DIR` override).
- Registers `com.secreta.agent` under `~/Library/LaunchAgents` to start the bundled daemon.
- Removes any stale `/tmp/secreta.sock` and restarts the agent to recreate it.

```bash
./scripts/install.sh
```

You can uninstall and remove the LaunchAgent with:

```bash
./scripts/uninstall.sh
```

If you need custom paths, set `INSTALL_DIR`, `APP_INSTALL_DIR`, and/or `LAUNCH_AGENTS_DIR` when running the scripts.

## Logs

Audit logs are emitted through macOS unified logging under the `com.secreta` subsystem.

```bash
/usr/bin/log show --info --predicate 'subsystem == "com.secreta"' --last 10m
```

## CLI

Use the direct commands for quick manual testing.

```bash
secreta create --name demo --value test
secreta fetch --name demo
secreta delete --name demo
secreta file edit /path/to/myfile.secret
secreta file read /path/to/myfile.secret
```

Options:

- `--socket` override the Unix socket path (default: /tmp/secreta.sock)
- `--cache-seconds` cache TTL for create
- `--reason` access reason for fetch
- `delete` requires `--name`
- `status` checks the socket health
- `file edit <path>` opens an encrypted file editor
- `file read <path>` prints the decrypted contents

File editing notes:

- Uses `$EDITOR`, then `$VISUAL`, then `/usr/bin/vi`.
- The file is stored encrypted at rest and saved on editor exit.
- The per-file encryption key is stored as a normal secret named `sa:ek_<random>` and the key name is embedded in the file.
- Moving the file preserves access because the key name travels with the encrypted payload.
- Files must be created or re-saved with the current format (v2).

## SDK

### Go

Install the Go module from this repo and use the client helper to call the socket API:

```bash
go get github.com/jptrs93/secreta/sdk/go/secreta
```

```go
package main

import (
    "fmt"
    "github.com/jptrs93/secreta/sdk/go/secreta"
)

func main() {
    response, err := secreta.FetchSecret("demo", "testing")
    if err != nil {
        panic(err)
    }
    fmt.Println(response.SecretValue)

    fileResponse, err := secreta.ReadFile("/path/to/myfile.secret", "testing")
    if err != nil {
        panic(err)
    }
    fmt.Println(fileResponse.Plaintext)
}
```
