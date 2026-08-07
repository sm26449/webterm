# Signed agent updates

The gateway can push a new `agent/ptyd.py` to every host it manages. That is a code-execution
channel into your whole fleet, so it is the part of the system with the most deliberate design.

## The chain

Every update carries an Ed25519 signature. The agent verifies it against `UPDATE_PUBKEY`, a
constant compiled into the copy of `ptyd.py` running on that host, and refuses anything that does
not verify. The verifier is hand-rolled in the agent (pure stdlib, RFC 8032, with canonical-S and
on-curve checks) so the agent keeps its "one file, no dependencies" property.

Two further rules close the obvious gaps:

- **Anti-rollback.** An update whose `AGENT_VERSION` is lower than the running one is refused even
  with a valid signature. Otherwise a compromised gateway could replay an old, correctly signed
  release to reintroduce a fixed vulnerability.
- **Validation before replacement.** The new source is written to a probe file and executed with
  `selftest` in a subprocess *while the old agent is still running*. Only if it starts cleanly is
  it moved into place. A signature proves who sent the code, not that it works; without this
  check, one bad release would put every host into a restart loop that only physical or SSH
  access could break.

## Whose key?

This is the part worth reading carefully, because the answer changed.

Each **deployment** generates its own Ed25519 key at first boot, stored in the data volume. When
the gateway serves the agent source — at install and on every update — it substitutes its own
public key into `UPDATE_PUBKEY` and signs with its private half. Agents therefore trust *your*
gateway, not the project.

The project's own key still signs the copy in the repository. That is the **official channel**: a
fallback for a deployment that has no key of its own. In practice a fresh install always has one,
so this path is for recovery, not normal operation.

What this buys, stated honestly:

- a network MITM cannot install code — it has no key;
- a compromised upstream cannot install code on your fleet — your agents trust your key;
- **a compromised gateway can.** It is the trust anchor for its own fleet, by design. The
  mitigations are a passphrase on the key (auto-update then pauses until you unlock it) and
  treating the data volume as key material.

The mechanism used to be justified by "the gateway never holds the private key". Per-deployment
keys made that false, and the sentence survived the change that invalidated it. If you find
yourself relying on a comment here, check that its premise still holds.

## Rotating the key without touching a host

Rotation looks like it should require reinstalling every agent. It does not.

An agent verifies an update against the key it currently holds, and never inspects which key the
new file embeds. So an update **signed by the outgoing key** whose content **carries the incoming
key** is accepted, and the agent restarts trusting the new one. No host is touched and tmux
sessions survive.

The procedure:

1. Generate the new key pair offline. Put the new public key in `agent/ptyd.py` and bump
   `AGENT_VERSION` — without a bump the gateway pushes nothing and the rotation silently does not
   happen.
2. Sign with the **outgoing** key: the one the deployed agents carry, not the new one. This is the
   single mistake that would lock out the whole fleet.
3. Run `scripts/check-rollover.py`. It verifies the signature matches the file, that the signer is
   the key the deployed fleet actually holds (read from the deployed tag, not assumed), and that
   the version grew.
4. Deploy. Agents update themselves.
5. **Only after every agent is on the new version**, put the new private key on the gateway.
   Earlier, agents still on the old key would correctly refuse updates signed with the new one.

   This step is a file operation, not an API call: `/api/signing/import` returns 409 while a key
   exists, and no endpoint deletes one. Replace `data/agent-signing.key` (mode `600`) and restart
   the gateway, which loads an unencrypted key at boot. The awkwardness is a guard — swapping the
   trust anchor of an entire fleet should not be one button in a web UI.

`agent/ptyd.py.signer` records which key produced `agent/ptyd.py.sig`. During a rotation it
differs from the key in the file, on purpose — CI verifies against the declared signer so the
"did you forget to re-sign?" check keeps working in both cases.

## Forks

A fork that modifies the agent cannot re-sign with the project key and does not need to: its own
instance generates a key at first boot and re-signs in memory on every push, never reading the
repository signature. The CI signature gate is release hygiene for the canonical repository and
warns rather than fails elsewhere.
