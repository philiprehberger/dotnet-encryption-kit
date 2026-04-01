# Philiprehberger.EncryptionKit

[![CI](https://github.com/philiprehberger/dotnet-encryption-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/dotnet-encryption-kit/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Philiprehberger.EncryptionKit.svg)](https://www.nuget.org/packages/Philiprehberger.EncryptionKit)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/dotnet-encryption-kit)](https://github.com/philiprehberger/dotnet-encryption-kit/commits/main)

AES-256-GCM encryption with key generation, sealed envelopes, PBKDF2 key derivation, streaming, and key rotation.

## Installation

```bash
dotnet add package Philiprehberger.EncryptionKit
```

## Usage

```csharp
using Philiprehberger.EncryptionKit;

var encrypted = Encryption.Encrypt("Hello, World!", "my-secret-password");
var decrypted = Encryption.Decrypt(encrypted, "my-secret-password");

Console.WriteLine(decrypted); // "Hello, World!"
```

### Encrypt and Decrypt Bytes

```csharp
using Philiprehberger.EncryptionKit;

byte[] data = [0x01, 0x02, 0x03, 0x04];

byte[] encrypted = Encryption.Encrypt(data, "my-secret-password");
byte[] decrypted = Encryption.Decrypt(encrypted, "my-secret-password");
```

### Stream Encryption

```csharp
using Philiprehberger.EncryptionKit;

await using var inputFile = File.OpenRead("largefile.dat");
await using var encryptedFile = File.Create("largefile.enc");

await Encryption.EncryptStreamAsync(inputFile, encryptedFile, "my-secret-password");

encryptedFile.Position = 0;
await using var decryptedFile = File.Create("largefile.dec");

await Encryption.DecryptStreamAsync(encryptedFile, decryptedFile, "my-secret-password");
```

### Key Rotation

```csharp
using Philiprehberger.EncryptionKit;

var encrypted = Encryption.Encrypt("sensitive data", "old-password");
var rotated = Encryption.ReEncrypt(encrypted, "old-password", "new-password");
var decrypted = Encryption.Decrypt(rotated, "new-password");
```

### Additional Authenticated Data (AAD)

```csharp
using Philiprehberger.EncryptionKit;

var aad = new byte[] { 0x01, 0x02, 0x03 };
var options = new EncryptionOptions(AssociatedData: aad);

var encrypted = Encryption.Encrypt("authenticated data", "password", options);
var decrypted = Encryption.Decrypt(encrypted, "password", options);
```

### Key Generation

```csharp
using Philiprehberger.EncryptionKit;

byte[] key = KeyGenerator.GenerateKey();       // 256-bit key
byte[] key128 = KeyGenerator.GenerateKey(128); // 128-bit key
byte[] nonce = KeyGenerator.GenerateNonce();   // 12-byte nonce
byte[] salt = KeyGenerator.GenerateSalt();     // 16-byte salt
```

### Sealed Envelopes

```csharp
using Philiprehberger.EncryptionKit;

// Seal plaintext into a self-describing envelope
byte[] envelope = SealedEnvelope.Seal("sensitive data", "my-password");

// Open the envelope to get plaintext back
string decrypted = SealedEnvelope.OpenString(envelope, "my-password");

// Works with byte arrays too
byte[] data = new byte[] { 0x01, 0x02, 0x03 };
byte[] sealed = SealedEnvelope.Seal(data, "my-password");
byte[] opened = SealedEnvelope.Open(sealed, "my-password");
```

### Custom Options

```csharp
using Philiprehberger.EncryptionKit;

var options = new EncryptionOptions(Iterations: 200_000);

var encrypted = Encryption.Encrypt("sensitive data", "password", options);
var decrypted = Encryption.Decrypt(encrypted, "password", options);
```

## API

### `Encryption`

| Method | Description |
|--------|-------------|
| `Encrypt(string, string)` | Encrypts a string, returns base64-encoded ciphertext |
| `Encrypt(string, string, EncryptionOptions)` | Encrypts a string with custom options |
| `Decrypt(string, string)` | Decrypts a base64-encoded ciphertext string |
| `Decrypt(string, string, EncryptionOptions)` | Decrypts a string with custom options |
| `Encrypt(byte[], string)` | Encrypts a byte array |
| `Encrypt(byte[], string, EncryptionOptions)` | Encrypts a byte array with custom options |
| `Decrypt(byte[], string)` | Decrypts a byte array |
| `Decrypt(byte[], string, EncryptionOptions)` | Decrypts a byte array with custom options |
| `ReEncrypt(string, string, string, EncryptionOptions?)` | Decrypts with old password and re-encrypts with new password |
| `EncryptStreamAsync(Stream, Stream, string, EncryptionOptions?, CancellationToken)` | Encrypts a stream in chunks |
| `DecryptStreamAsync(Stream, Stream, string, EncryptionOptions?, CancellationToken)` | Decrypts a stream in chunks |

### `KeyGenerator`

| Method | Description |
|--------|-------------|
| `GenerateKey(int)` | Generates a cryptographically secure random key (128, 192, or 256 bits) |
| `GenerateNonce(int)` | Generates a cryptographically secure random nonce |
| `GenerateSalt(int)` | Generates a cryptographically secure random salt |

### `SealedEnvelope`

| Method | Description |
|--------|-------------|
| `Seal(byte[], string, EncryptionOptions?)` | Encrypts data into a self-describing envelope |
| `Seal(string, string, EncryptionOptions?)` | Encrypts a string into a self-describing envelope |
| `Open(byte[], string, byte[]?)` | Opens a sealed envelope and returns decrypted bytes |
| `OpenString(byte[], string, byte[]?)` | Opens a sealed envelope and returns a decrypted string |

### `EncryptionAlgorithm`

| Value | Description |
|-------|-------------|
| `AesGcm` | AES-256-GCM authenticated encryption |

### `EncryptionOptions`

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Iterations` | `int` | `100_000` | PBKDF2 iterations for key derivation |
| `SaltLength` | `int` | `16` | Random salt length in bytes |
| `NonceLength` | `int` | `12` | Random nonce length in bytes |
| `TagLength` | `int` | `16` | Authentication tag length in bytes |
| `AssociatedData` | `byte[]?` | `null` | Optional additional authenticated data for AES-GCM |

## Development

```bash
dotnet build src/Philiprehberger.EncryptionKit.csproj --configuration Release
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/dotnet-encryption-kit)

🐛 [Report issues](https://github.com/philiprehberger/dotnet-encryption-kit/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/dotnet-encryption-kit/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
