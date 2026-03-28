using System.Security.Cryptography;
using System.Text;

namespace Philiprehberger.EncryptionKit;

/// <summary>
/// Provides AES-256-GCM encryption and decryption with automatic PBKDF2 key derivation,
/// random nonce generation, authenticated encryption, and optional version headers.
/// </summary>
public static class Encryption
{
    private static readonly EncryptionOptions DefaultOptions = new();

    private const int KeyLength = 32; // 256 bits

    /// <summary>
    /// The current encryption format version byte. Version 0x01 represents AES-256-GCM
    /// with PBKDF2 key derivation.
    /// </summary>
    public const byte CurrentVersion = 0x01;

    private const int DefaultStreamBufferSize = 81920; // 80 KB chunks

    /// <summary>
    /// Encrypts a plaintext string using AES-256-GCM with PBKDF2 key derivation.
    /// </summary>
    /// <param name="plaintext">The plaintext string to encrypt.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <returns>A base64-encoded string containing the version header, salt, nonce, ciphertext, and authentication tag.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="plaintext"/> or <paramref name="password"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="plaintext"/> or <paramref name="password"/> is empty.</exception>
    public static string Encrypt(string plaintext, string password)
    {
        return Encrypt(plaintext, password, DefaultOptions);
    }

    /// <summary>
    /// Encrypts a plaintext string using AES-256-GCM with PBKDF2 key derivation and custom options.
    /// </summary>
    /// <param name="plaintext">The plaintext string to encrypt.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <param name="options">Custom encryption options.</param>
    /// <returns>A base64-encoded string containing the version header, salt, nonce, ciphertext, and authentication tag.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="plaintext"/>, <paramref name="password"/>, or <paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="plaintext"/> or <paramref name="password"/> is empty.</exception>
    public static string Encrypt(string plaintext, string password, EncryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var data = Encoding.UTF8.GetBytes(plaintext);
        var encrypted = Encrypt(data, password, options);

        return Convert.ToBase64String(encrypted);
    }

    /// <summary>
    /// Decrypts a base64-encoded ciphertext string using AES-256-GCM with PBKDF2 key derivation.
    /// </summary>
    /// <param name="ciphertext">The base64-encoded string containing the version header, salt, nonce, ciphertext, and authentication tag.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <returns>The decrypted plaintext string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ciphertext"/> or <paramref name="password"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ciphertext"/> or <paramref name="password"/> is empty.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails due to an invalid password or corrupted data.</exception>
    public static string Decrypt(string ciphertext, string password)
    {
        return Decrypt(ciphertext, password, DefaultOptions);
    }

    /// <summary>
    /// Decrypts a base64-encoded ciphertext string using AES-256-GCM with PBKDF2 key derivation and custom options.
    /// </summary>
    /// <param name="ciphertext">The base64-encoded string containing the version header, salt, nonce, ciphertext, and authentication tag.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <param name="options">Custom encryption options matching those used during encryption.</param>
    /// <returns>The decrypted plaintext string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ciphertext"/>, <paramref name="password"/>, or <paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ciphertext"/> or <paramref name="password"/> is empty.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails due to an invalid password or corrupted data.</exception>
    public static string Decrypt(string ciphertext, string password, EncryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(ciphertext);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var data = Convert.FromBase64String(ciphertext);
        var decrypted = Decrypt(data, password, options);

        return Encoding.UTF8.GetString(decrypted);
    }

    /// <summary>
    /// Encrypts a byte array using AES-256-GCM with PBKDF2 key derivation.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <returns>A byte array containing the version header, salt, nonce, ciphertext, and authentication tag.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> or <paramref name="password"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is empty.</exception>
    public static byte[] Encrypt(byte[] data, string password)
    {
        return Encrypt(data, password, DefaultOptions);
    }

    /// <summary>
    /// Encrypts a byte array using AES-256-GCM with PBKDF2 key derivation and custom options.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <param name="options">Custom encryption options.</param>
    /// <returns>A byte array containing the version header, salt, nonce, ciphertext, and authentication tag.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/>, <paramref name="password"/>, or <paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is empty.</exception>
    public static byte[] Encrypt(byte[] data, string password, EncryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var salt = new byte[options.SaltLength];
        RandomNumberGenerator.Fill(salt);

        var key = DeriveKey(password, salt, options.Iterations);

        var nonce = new byte[options.NonceLength];
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[data.Length];
        var tag = new byte[options.TagLength];

        using var aes = new AesGcm(key, options.TagLength);
        aes.Encrypt(nonce, data, ciphertext, tag, options.AssociatedData);

        // Pack as: version + salt + nonce + ciphertext + tag
        var result = new byte[1 + salt.Length + nonce.Length + ciphertext.Length + tag.Length];
        var offset = 0;

        result[offset] = CurrentVersion;
        offset += 1;

        Buffer.BlockCopy(salt, 0, result, offset, salt.Length);
        offset += salt.Length;

        Buffer.BlockCopy(nonce, 0, result, offset, nonce.Length);
        offset += nonce.Length;

        Buffer.BlockCopy(ciphertext, 0, result, offset, ciphertext.Length);
        offset += ciphertext.Length;

        Buffer.BlockCopy(tag, 0, result, offset, tag.Length);

        CryptographicOperations.ZeroMemory(key);

        return result;
    }

    /// <summary>
    /// Decrypts a byte array using AES-256-GCM with PBKDF2 key derivation.
    /// </summary>
    /// <param name="data">The byte array containing the version header, salt, nonce, ciphertext, and authentication tag.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> or <paramref name="password"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is empty or <paramref name="data"/> is too short.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails due to an invalid password or corrupted data.</exception>
    public static byte[] Decrypt(byte[] data, string password)
    {
        return Decrypt(data, password, DefaultOptions);
    }

    /// <summary>
    /// Decrypts a byte array using AES-256-GCM with PBKDF2 key derivation and custom options.
    /// </summary>
    /// <param name="data">The byte array containing the version header, salt, nonce, ciphertext, and authentication tag.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <param name="options">Custom encryption options matching those used during encryption.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/>, <paramref name="password"/>, or <paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is empty or <paramref name="data"/> is too short.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails due to an invalid password, corrupted data, or mismatched associated data.</exception>
    public static byte[] Decrypt(byte[] data, string password, EncryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(password);

        // version byte + salt + nonce + tag (minimum, no ciphertext)
        var headerLength = 1 + options.SaltLength + options.NonceLength + options.TagLength;

        if (data.Length < headerLength)
        {
            throw new ArgumentException(
                $"Encrypted data is too short. Expected at least {headerLength} bytes, got {data.Length}.",
                nameof(data));
        }

        var offset = 0;

        var version = data[offset];
        offset += 1;

        if (version != CurrentVersion)
        {
            throw new CryptographicException(
                $"Unsupported encryption format version: 0x{version:X2}. Expected 0x{CurrentVersion:X2}.");
        }

        var salt = new byte[options.SaltLength];
        Buffer.BlockCopy(data, offset, salt, 0, salt.Length);
        offset += salt.Length;

        var nonce = new byte[options.NonceLength];
        Buffer.BlockCopy(data, offset, nonce, 0, nonce.Length);
        offset += nonce.Length;

        var ciphertextLength = data.Length - headerLength;
        var ciphertext = new byte[ciphertextLength];
        Buffer.BlockCopy(data, offset, ciphertext, 0, ciphertextLength);
        offset += ciphertextLength;

        var tag = new byte[options.TagLength];
        Buffer.BlockCopy(data, offset, tag, 0, tag.Length);

        var key = DeriveKey(password, salt, options.Iterations);
        var plaintext = new byte[ciphertextLength];

        using var aes = new AesGcm(key, options.TagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, options.AssociatedData);

        CryptographicOperations.ZeroMemory(key);

        return plaintext;
    }

    /// <summary>
    /// Decrypts ciphertext with the old password and re-encrypts it with a new password.
    /// Useful for password rotation without exposing the plaintext to calling code.
    /// </summary>
    /// <param name="ciphertext">The base64-encoded ciphertext encrypted with <paramref name="oldPassword"/>.</param>
    /// <param name="oldPassword">The current password used to decrypt the data.</param>
    /// <param name="newPassword">The new password to encrypt the data with.</param>
    /// <param name="options">Optional encryption options. Applied to both decryption and re-encryption.</param>
    /// <returns>A base64-encoded string containing the data re-encrypted with the new password.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when any password is empty.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption with the old password fails.</exception>
    public static string ReEncrypt(string ciphertext, string oldPassword, string newPassword, EncryptionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(oldPassword);
        ArgumentNullException.ThrowIfNull(newPassword);
        ArgumentException.ThrowIfNullOrEmpty(ciphertext);
        ArgumentException.ThrowIfNullOrEmpty(oldPassword);
        ArgumentException.ThrowIfNullOrEmpty(newPassword);

        var effectiveOptions = options ?? DefaultOptions;

        var plaintext = Decrypt(ciphertext, oldPassword, effectiveOptions);
        return Encrypt(plaintext, newPassword, effectiveOptions);
    }

    /// <summary>
    /// Encrypts data from an input stream and writes the encrypted output to another stream.
    /// Processes data in chunks to support large files without loading entirely into memory.
    /// </summary>
    /// <param name="input">The input stream containing plaintext data to encrypt.</param>
    /// <param name="output">The output stream where encrypted data will be written.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <param name="options">Optional encryption options.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A task representing the asynchronous encryption operation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="input"/>, <paramref name="output"/>, or <paramref name="password"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is empty.</exception>
    public static async Task EncryptStreamAsync(
        Stream input,
        Stream output,
        string password,
        EncryptionOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var effectiveOptions = options ?? DefaultOptions;

        var salt = new byte[effectiveOptions.SaltLength];
        RandomNumberGenerator.Fill(salt);

        var key = DeriveKey(password, salt, effectiveOptions.Iterations);

        try
        {
            // Write version header
            output.WriteByte(CurrentVersion);

            // Write salt
            await output.WriteAsync(salt, cancellationToken).ConfigureAwait(false);

            // Read input in chunks, encrypt each chunk separately
            var buffer = new byte[DefaultStreamBufferSize];
            int bytesRead;

            while ((bytesRead = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false)) > 0)
            {
                var chunk = new byte[bytesRead];
                Buffer.BlockCopy(buffer, 0, chunk, 0, bytesRead);

                var nonce = new byte[effectiveOptions.NonceLength];
                RandomNumberGenerator.Fill(nonce);

                var ciphertext = new byte[bytesRead];
                var tag = new byte[effectiveOptions.TagLength];

                using var aes = new AesGcm(key, effectiveOptions.TagLength);
                aes.Encrypt(nonce, chunk, ciphertext, tag, effectiveOptions.AssociatedData);

                // Write chunk length (4 bytes, big-endian)
                var lengthBytes = BitConverter.GetBytes(bytesRead);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(lengthBytes);
                }
                await output.WriteAsync(lengthBytes, cancellationToken).ConfigureAwait(false);

                // Write nonce + ciphertext + tag
                await output.WriteAsync(nonce, cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(ciphertext, cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Decrypts data from an input stream and writes the decrypted output to another stream.
    /// Processes data in chunks to support large files without loading entirely into memory.
    /// </summary>
    /// <param name="input">The input stream containing encrypted data.</param>
    /// <param name="output">The output stream where decrypted data will be written.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <param name="options">Optional encryption options matching those used during encryption.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A task representing the asynchronous decryption operation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="input"/>, <paramref name="output"/>, or <paramref name="password"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is empty.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails due to an invalid password, corrupted data, or unsupported version.</exception>
    public static async Task DecryptStreamAsync(
        Stream input,
        Stream output,
        string password,
        EncryptionOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var effectiveOptions = options ?? DefaultOptions;

        // Read version header
        var versionByte = input.ReadByte();
        if (versionByte == -1)
        {
            throw new CryptographicException("Encrypted stream is empty.");
        }

        if ((byte)versionByte != CurrentVersion)
        {
            throw new CryptographicException(
                $"Unsupported encryption format version: 0x{(byte)versionByte:X2}. Expected 0x{CurrentVersion:X2}.");
        }

        // Read salt
        var salt = new byte[effectiveOptions.SaltLength];
        await ReadExactAsync(input, salt, cancellationToken).ConfigureAwait(false);

        var key = DeriveKey(password, salt, effectiveOptions.Iterations);

        try
        {
            var lengthBytes = new byte[4];

            while (true)
            {
                // Try to read chunk length
                var lengthBytesRead = 0;
                while (lengthBytesRead < 4)
                {
                    var read = await input.ReadAsync(
                        lengthBytes.AsMemory(lengthBytesRead, 4 - lengthBytesRead),
                        cancellationToken).ConfigureAwait(false);

                    if (read == 0)
                    {
                        if (lengthBytesRead == 0)
                        {
                            return; // End of stream, all chunks processed
                        }

                        throw new CryptographicException("Unexpected end of encrypted stream.");
                    }

                    lengthBytesRead += read;
                }

                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(lengthBytes);
                }
                var chunkLength = BitConverter.ToInt32(lengthBytes, 0);

                if (chunkLength <= 0 || chunkLength > DefaultStreamBufferSize)
                {
                    throw new CryptographicException("Invalid chunk length in encrypted stream.");
                }

                // Read nonce
                var nonce = new byte[effectiveOptions.NonceLength];
                await ReadExactAsync(input, nonce, cancellationToken).ConfigureAwait(false);

                // Read ciphertext
                var ciphertext = new byte[chunkLength];
                await ReadExactAsync(input, ciphertext, cancellationToken).ConfigureAwait(false);

                // Read tag
                var tag = new byte[effectiveOptions.TagLength];
                await ReadExactAsync(input, tag, cancellationToken).ConfigureAwait(false);

                var plaintext = new byte[chunkLength];

                using var aes = new AesGcm(key, effectiveOptions.TagLength);
                aes.Decrypt(nonce, ciphertext, tag, plaintext, effectiveOptions.AssociatedData);

                await output.WriteAsync(plaintext, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = await stream.ReadAsync(
                buffer.AsMemory(totalRead, buffer.Length - totalRead),
                cancellationToken).ConfigureAwait(false);

            if (read == 0)
            {
                throw new CryptographicException("Unexpected end of encrypted stream.");
            }

            totalRead += read;
        }
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA256);

        return pbkdf2.GetBytes(KeyLength);
    }
}
