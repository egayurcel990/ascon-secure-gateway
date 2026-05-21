# Security Model

## Assets Protected

The system protects sensitive API payloads, especially authentication data such as username, password, and session token.

## Main Security Goals

1. Confidentiality: sensitive request and response data should not be readable in network capture.
2. Integrity: modified ciphertext must be rejected.
3. Replay protection: reused encrypted requests must be rejected.
4. Network isolation: the internal web application must not be exposed directly to the host.

## Trusted Components

- Client demo script that holds the pre-shared key.
- Gateway service that decrypts, validates, and forwards requests.
- Internal web application reachable only from the Docker internal network.

## Adversary Model

The assumed attacker can observe and replay network traffic on the gateway port. The attacker may also attempt to modify ciphertext, nonce, tag, or AAD fields.

The current prototype does not assume a compromised gateway, compromised client machine, or leaked pre-shared key.

## Implemented Protections

- ASCON-AEAD128 encryption for application-layer payload protection.
- Authentication tag validation before plaintext is accepted.
- Associated Data validation for path, method, timestamp, client ID, and request ID.
- Replay cache for previously seen request IDs.
- Timestamp window validation.
- Docker internal network to hide the web application from direct host access.

## Known Limitations

- Replay cache is in-memory and resets when the gateway container restarts.
- Multi-gateway deployments require a shared replay cache, such as Redis.
- Key rotation is represented by `key_id`, but automated rotation is not implemented yet.
- Password hashing in the internal web application should be upgraded for production use.
