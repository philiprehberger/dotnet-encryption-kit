namespace Philiprehberger.EncryptionKit;

/// <summary>
/// Configuration options for AES-256-GCM encryption operations.
/// </summary>
/// <param name="Iterations">Number of PBKDF2 iterations for key derivation. Default is 100,000.</param>
/// <param name="SaltLength">Length of the random salt in bytes. Default is 16.</param>
/// <param name="NonceLength">Length of the random nonce in bytes. Default is 12.</param>
/// <param name="TagLength">Length of the authentication tag in bytes. Default is 16.</param>
/// <param name="AssociatedData">Optional additional authenticated data (AAD) for AES-GCM. Must match on decryption.</param>
public record EncryptionOptions(
    int Iterations = 100_000,
    int SaltLength = 16,
    int NonceLength = 12,
    int TagLength = 16,
    byte[]? AssociatedData = null);
