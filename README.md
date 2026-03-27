# Philiprehberger.EncryptionKit

[![CI](https://github.com/philiprehberger/dotnet-encryption-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/dotnet-encryption-kit/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Philiprehberger.EncryptionKit.svg)](https://www.nuget.org/packages/Philiprehberger.EncryptionKit)
[![License](https://img.shields.io/github/license/philiprehberger/dotnet-encryption-kit)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-GitHub%20Sponsors-ec6cb9)](https://github.com/sponsors/philiprehberger)

Simple AES-256-GCM encryption and decryption with automatic key derivation and nonce management.

## Installation

```bash
dotnet add package Philiprehberger.EncryptionKit
```

## Usage

### Encrypt and Decrypt Strings

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

### Custom Options

```csharp
using Philiprehberger.EncryptionKit;

var options = new EncryptionOptions(Iterations: 200_000);

var encrypted = Encryption.Encrypt("sensitive data", "password", options);
var decrypted = Encryption.Decrypt(encrypted, "password", options);
```

## API

| Method | Description |
|--------|-------------|
| `Encryption.Encrypt(string, string)` | Encrypts a string, returns base64-encoded ciphertext |
| `Encryption.Encrypt(string, string, EncryptionOptions)` | Encrypts a string with custom options |
| `Encryption.Decrypt(string, string)` | Decrypts a base64-encoded ciphertext string |
| `Encryption.Decrypt(string, string, EncryptionOptions)` | Decrypts a string with custom options |
| `Encryption.Encrypt(byte[], string)` | Encrypts a byte array |
| `Encryption.Encrypt(byte[], string, EncryptionOptions)` | Encrypts a byte array with custom options |
| `Encryption.Decrypt(byte[], string)` | Decrypts a byte array |
| `Encryption.Decrypt(byte[], string, EncryptionOptions)` | Decrypts a byte array with custom options |

| Record | Fields |
|--------|--------|
| `EncryptionOptions` | `Iterations` (default 100,000), `SaltLength` (default 16), `NonceLength` (default 12), `TagLength` (default 16) |

## Development

```bash
dotnet build src/Philiprehberger.EncryptionKit.csproj --configuration Release
```

## License

[MIT](LICENSE)
