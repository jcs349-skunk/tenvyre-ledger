# tenvyre-ledger

TENVYRE's audit ledger: timestamped fingerprints of every call, before the game.

TENVYRE makes calls about head-to-head fantasy baseball: each week's chance to win a matchup, start and sit calls,
pickups, player projections. Anyone can show a good record after the fact. This ledger is how TENVYRE proves its record
wasn't edited, trimmed or picked afterwards.

## How it works

Every hour during the season, every new call is sealed in a private repository and fingerprinted:

- each call gets a random **salt** and is hashed (`sha256`), so nobody can guess a call from its fingerprint;
- the hour's fingerprints are combined into one **root** (a Merkle tree), which commits to every call **and to how many
  there were**;
- the root is **time-stamped by two outside services**: an RFC 3161 timestamping authority (FreeTSA), which signs the
  time to the second, and OpenTimestamps, which anchors it to Bitcoin within hours.

Only the roots, the counts and the two timestamp files are published here. An hour with no new calls still publishes
a root (a "heartbeat"), so a missing hour would show.

Later, calls are **revealed** with their salt and proof, so anyone can check them against the root published before
the game. Some are revealed a week after they're made; others are revealed by a sample drawn after the season from a
public random beacon (drand), at a round fixed before the season began, so the sample can't be chosen.

## What's here

| path | what it is |
|---|---|
| `roots/<YYYY-MM>/<batch>.json` | a batch: its id, time, root and number of calls |
| `roots/<YYYY-MM>/<batch>.tsr` | its RFC 3161 timestamp (signed by the authority) |
| `roots/<YYYY-MM>/<batch>.ots` | its OpenTimestamps proof (pending until its Bitcoin anchor lands) |
| `summary.json` | the running counts: calls committed, batches, timestamps, and whether the roots add up |
| `reveals/` | revealed calls, each with its salt and proof (none yet) |
| `verify.mjs`, `commit.mjs`, `timestamp.mjs` | the verifier |

Nothing here names a league, a team or a manager. The engine that makes the calls stays private; only its outputs are
audited.

## Check a call yourself

You need Node 18 or later. Nothing to install.

```bash
git clone https://github.com/jcs349-skunk/tenvyre-ledger.git
cd tenvyre-ledger
node verify.mjs reveals/<YYYY-MM>/<batch>/<call>.json
```

It checks that:

1. the call is well formed, and its fingerprint is right;
2. the fingerprint reaches the batch's published root, for the published number of calls;
3. the RFC 3161 timestamp is granted, is for that root, and shows the time this ledger prints;
4. the OpenTimestamps proof is for that root;
5. with `--before <time>`, the call was timestamped before that time (a game's first pitch, from MLB's schedule).

Two checks use standard outside tools, and the verifier prints the exact command when it can't run them:

- **the authority's signature**: `--tsa-ca <file>` with FreeTSA's certificate (https://freetsa.org/files/cacert.pem),
  checked by `openssl ts -verify`;
- **the Bitcoin anchor**: the OpenTimestamps client (`pip install opentimestamps-client`), then `ots verify <file>.ots`.

A step it can't run is reported as "not checked", never as passed.

## Licence

MIT. See `LICENSE`.
