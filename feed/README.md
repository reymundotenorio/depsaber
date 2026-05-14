# DepSaber Intelligence Feed

`base.json` is unsigned source material for DepSaber's embedded and hosted intelligence feed.

External feeds loaded with `depsaber update --source <file-or-url>` must include an Ed25519 `signature` field. DepSaber verifies the signature against the canonical payload formed from `version`, `issuedAt`, `expiresAt`, and `rules`.

## Signing Model

1. Maintain feed source as JSON without `signature`.
2. Sign the canonical payload with an offline Ed25519 private key.
3. Publish the signed feed JSON over HTTPS.
4. Set `DEPSABER_FEED_PUBLIC_KEY_BASE64` to the matching Ed25519 public key before updating from that source.

## Freshness

Every feed must include `issuedAt` and `expiresAt`. DepSaber rejects expired feeds so stale intelligence cannot silently replace current rules.

## Safety Rules

- Never publish unsigned external feeds.
- Never store private signing keys in this repository.
- Keep `expiresAt` short enough that stale mirrors fail closed.
- Review every new rule against public source references before signing.
