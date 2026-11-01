# Continuity-Engine

Profile ingestion for The Omniverse. The Continuity Engine takes profiles from the daemons living on each device and from other sources the user imports, combines them into one newsfeed-based profile, and readies it for the Continuum application.

## Where it sits
- **Omni daemon**: the networked protocol on each device
- **Continuity Engine (this repo)**: ingests profiles and combines them across daemons
- **Omni-Hub**: the superapp container the user sees

## Contents
- `integrations/continuity_social_import_engine.py`: imports social profiles and contacts, matches friends by blind hash, and signs profile deltas with Ed25519 in the canonical Omni-Daemon event format (same canonical JSON as Omni-Daemon `Admin/omni_signing.py`, so any daemon can verify them with `verify_event`)
- `integrations/zero_dep_continuity_social_import_engine.py`: **deprecated** shim that delegates to the Ed25519 engine. It used to sign with HMAC, which peers could not verify; real signatures need `cryptography`, so there is no longer a zero-dependency variant. Import `continuity_social_import_engine` instead.

`pip install cryptography`, then run `python3 integrations/continuity_social_import_engine.py` for the self-test, or `python3 -m unittest` from the repo root for the test suite.

### Signed event format
`{"event_id", "action": "PROFILE_SOCIAL_IMPORT", "author_pubkey", "previous_hash", "ts", "payload", "signature"}`
- signed bytes: `json.dumps({action, author_pubkey, payload, previous_hash, ts}, sort_keys=True, separators=(",", ":"))` as UTF-8
- `signature`: Ed25519 over those bytes, 128 hex; `author_pubkey`: raw public key, 64 hex; `ts`: int milliseconds
- `event_id`: `"0x" + sha256(signed bytes)`; `previous_hash`: the author's previous `event_id`, or `0x` + 64 zeros

Moved from kiroba/The-Omniverse with history, Oct 31 2026.
