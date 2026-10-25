# Proof of possession of the node key (English)

English version of the section "Dovada de posesie a cheii nodului" of `README.md` (Romanian).

## The problem

A `node_id` is `SHA-256(public key)[:16]`, and public keys are public (the member list shows them). The relay and the rendezvous server are not trusted for identity
(the handshake authenticates nodes by their static keys). Without a proof, a registration is accepted whenever its key matches the id, so anybody holding a token (point-to-point mode) or an
account (mesh) can register somebody else's public key with endpoints of its own, or register an id before its owner and lock the owner out. Data stays protected by the
handshake, so the harm is a denial of service, not a confidentiality break.

## The proof

The node keys are KEM keys (X25519 + ML-KEM-768), not signature keys, so the proof is a **challenge** only the holder of the private halves can open (`oneqpop.py`):

1. The node asks `POST /v1/c/<community>/nodes/<id>/challenge` (point-to-point: `POST /v1/nodes/<id>/challenge`) with its public key.
2. The server encapsulates to the node's ML-KEM key, does an ephemeral-to-static X25519 exchange, derives a key from both (plus the node id and a nonce) and seals a secret
   `R = HMAC(server_key, "R" | node_id | nonce | exp)` with it. The server keeps **no state**: in a federation the `server_key` is derived from the shared secret, so any relay
   verifies a challenge made by another one.
3. The node opens it and sends `proof = HMAC(R, "proof" | node_id | nonce | exp)` as `pop` in the registration. A proof is valid for 60 s; the client reuses it until shortly before it expires.

Rules:

| Case | Result |
|---|---|
| registration with a valid proof | accepted; the node record gets `pop: true` (replicated) |
| a node with `pop: true`, update without a proof | refused (403): also protects against downgrade |
| a forged, expired or other node's proof | refused (403) |
| no proof, record not protected, `require_pop` off | accepted (nodes without the feature keep working) |
| no proof, `require_pop` on | refused (403) |
| the administrator deletes the node | the id can be registered again |
| point-to-point: relay WebSocket slot of a verified node | needs `X-Oneq-Pop` (base64 of the proof) |
| a relay/server that answers 404 to the challenge request | the client registers without a proof |

Switches: `oneqrelay --require-pop` / `require_pop = yes` in `relay.conf`; `rendezvous_server --require-pop`. Turn it on once all nodes can give a proof.

## What it does not do

* It does not protect against a compromised relay (it can delete a node and give its address to another key; see the specification, section 12).
* It does not cover the rest of the request: it stops somebody who does *not* hold the key, not an attacker who can read the TLS stream.
* Without `require_pop`, a node that does not prove possession is accepted and can be squatted.
* An account holder who also has the key can register it, of course.
* The `oneqrelay` package needs `cryptography` (ML-KEM) for the challenge.

## Tests

`test_oneqpop.py` (21 tests): the codec (only the key holder answers, tampering with any field, other server keys, expiry, garbage), the mesh relay (downgrade protection, other node's proof, federation,
squatting a known public key, `require_pop`, nodes without the feature, reset by deleting), the Python node client (cache, expiry retry, relay without the feature, imposter) and the point-to-point rendezvous server
(overwrite, clients and servers without the feature, `require_pop`, relay slot, the relay client sending the proof by itself). Rust: unit test of `Identity::pop_answer` (`wire.rs`); the Rust and the Python
implementations answer each other's challenges.
