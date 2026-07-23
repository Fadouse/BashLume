# Official rule-pack verification keys

These raw hexadecimal Ed25519 public keys authorize dynamic probes only for correctly signed, structurally valid rule packs. Each source has an independent key.

| Pack | File | SHA-256 key ID |
|---|---|---|
| Bash | `bash-rules.pub` | `cc1bf0e554afb952f1e30a66f550b57bf0b687a629097a5efcfcf58d6c4171de` |
| Zsh | `zsh-rules.pub` | `1931a7b51afb724fb8d07a0e1ba734e84bd5bea47e3466394dd6051a9a54db46` |
| Fish | `fish-rules.pub` | `eb464340fd836b334118e62db22086e84b96d08c9eec87ec2d2a25931bf00a4e` |

Private keys are not stored in any repository. A rotation must add the new public key to the engine before signing a release with it; removal of the old key happens only after the overlap window and revocation review.
