# Continuity-Engine

Profile ingestion for The Omniverse. The Continuity Engine takes profiles from the daemons living on each device and from other sources the user imports, combines them into one newsfeed-based profile, and readies it for the Continuum application.

## Where it sits
- **Omni daemon**: the networked protocol on each device
- **Continuity Engine (this repo)**: ingests profiles and combines them across daemons
- **Omni-Hub**: the superapp container the user sees

## Contents
- `integrations/continuity_social_import_engine.py`: imports social profiles and contacts, matches friends by blind hash, and signs profile deltas with Ed25519
- `integrations/zero_dep_continuity_social_import_engine.py`: standard-library-only variant (HMAC, not yet verifiable by peers)

Run either file directly to run its self-test (`pip install cryptography` for the Ed25519 one).

Moved from kiroba/The-Omniverse with history, Oct 31 2026.
