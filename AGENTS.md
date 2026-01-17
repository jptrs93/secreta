# Agent Guide for secreta

Refer to `README.md` for the project summary and design overview.

## Important files and layout
- `Package.swift` is the build manifest.
- `Sources/Secreta/Secreta.swift` is the daemon entry point.
- `Sources/Secreta/SocketServer.swift` handles the Unix socket.
- `Sources/Secreta/SecretService.swift` implements create/access flows.
- `Sources/Secreta/KeychainAdapter.swift` wraps Keychain storage.
- `Sources/Secreta/PolicyEngine.swift` stores metadata and access data.
- `Sources/Secreta/CacheManager.swift` manages in-memory cache TTLs.
- `Sources/Secreta/AuthChallenge.swift` runs LocalAuthentication.
- `Sources/Secreta/Logging.swift` emits audit logs and notifications.
- `Sources/Secreta/Models.swift` contains request/response types.
- `Tests/SecretaTests/SecretaTests.swift` includes basic tests.

## Build, run, test
- Build: `swift build`
- Run (debug): `swift run secreta`
- Test all: `swift test`
- Test single: `swift test --filter SecretaTests/testHealthResponse`
- Test single (class): `swift test --filter SecretaTests`
- Lint/format: no tool configured yet

## Xcode usage
- This repo is a Swift package; open the root folder in Xcode to work.
- The executable product name is `secreta`.
- If you add an Xcode project, keep SPM as the source of truth.

## Socket API protocol
- Transport: Unix domain socket, length-prefixed JSON.
- Requests use `RequestEnvelope` with `requestId`, `method`, and `params`.
- Responses use `ResponseEnvelope` with `result` or `error`.
- Payloads are JSON encoded with ISO-8601 dates.

## Naming and structure
- Types: `UpperCamelCase` for structs/classes/enums.
- Methods and vars: `lowerCamelCase`.
- Files are named after their primary type.
- Prefer small single-responsibility types over large files.
- Keep core logic in `SecretService`, keep I/O in adapters.

## Imports
- Keep imports minimal and ordered by Apple framework name.
- Prefer `Foundation` first, then other frameworks.
- Avoid unused imports; remove them after refactors.

## Formatting
- 4-space indentation.
- Prefer explicit argument labels for clarity.
- Keep lines readable; break long lines when nested.
- Use trailing commas in multi-line literals.
- Avoid force unwraps except in tests.

## Types and modeling
- Use `struct` for value types and DTOs.
- Use `final class` for services and shared state.
- Prefer `Result<T, ServiceError>` for errorful responses.
- Model protocol payloads with `Codable` structs.
- Use `enum` for fixed string constants (methods, error codes).

## Error handling
- Map errors to `ErrorEnvelope` with `code`, `message`, `retryable`.
- Use `ServiceError` for domain errors in `SecretService`.
- Avoid throwing across the socket boundary; return error envelopes.
- Log failures with clear context (method, secret, client).

## Concurrency and queues
- Use dedicated serial queues for caches and policy state.
- Avoid blocking the main thread when doing I/O.
- Keep Network framework callbacks lightweight.
- If introducing async/await, ensure thread safety on shared stores.

## Keychain usage
- Store secrets as `sm:<cache_seconds>:<name>`.
- Use `kSecClassGenericPassword` items.
- Encode metadata in `kSecAttrGeneric` as JSON.
- Do not rely on Keychain ACL prompts for user auth.

## Cache and policy rules
- Cache key is `cdhash::secret_name`.
- Cache is in-memory only; resets on restart.
- `cache_seconds == 0` means auth required every access.
- Policy metadata is source of truth for cache TTL.

## Identity and audit
- Identity should resolve to CDHash + binary name/path.
- Audit log is emitted for every access attempt.
- Notifications should always include client, secret, result.
- Keep audit payloads JSON encoded for readability.

## Security notes
- Secrets must never be logged in plaintext.
- Avoid returning overly detailed error messages to clients.
- Ensure socket path is local-only and permissioned.
- Treat all client requests as untrusted input.

## Tests
- Add tests for cache TTL behavior and auth gating.
- Stub auth and keychain for deterministic tests.
- Keep tests independent of local hardware state.

## External rules
- No Cursor rules found.
- No Copilot instructions found.
