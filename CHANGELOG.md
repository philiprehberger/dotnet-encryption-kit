# Changelog

## 0.3.0 (2026-03-31)

- Add KeyGenerator for secure key, nonce, and salt generation
- Add SealedEnvelope for self-describing portable encrypted payloads
- Add EncryptionAlgorithm enum for algorithm identification

## 0.2.1 (2026-03-31)

- Standardize README to 3-badge format with emoji Support section
- Update CI actions to v5 for Node.js 24 compatibility

## 0.2.0 (2026-03-28)

- Add stream encryption and decryption via `EncryptStreamAsync` and `DecryptStreamAsync` for large file processing
- Add key rotation via `ReEncrypt` to decrypt with old password and re-encrypt with new password
- Add additional authenticated data (AAD) support via `AssociatedData` option in `EncryptionOptions`
- Add encryption version header byte (0x01) prepended to all ciphertext output for format versioning
- Add missing GitHub compliance files (issue templates, dependabot, PR template)
- Add 8 badges and Support section to README

## 0.1.5 (2026-03-26)

- Add Sponsor badge and fix License link format in README

## 0.1.4 (2026-03-24)

- Add unit tests
- Add test step to CI workflow

## 0.1.3 (2026-03-23)

- Shorten package description to meet 120-character limit

## 0.1.2 (2026-03-22)

- Fix README badge order to CI, NuGet, License

## 0.1.1 (2026-03-22)

- Improve README compliance: remove Requirements section, simplify Development section, fix License format
- Add dates to changelog entries

## 0.1.0 (2026-03-21)

- Initial release
- AES-256-GCM encryption and decryption
- PBKDF2 key derivation from password
- Automatic nonce and salt management
