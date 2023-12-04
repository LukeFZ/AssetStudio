using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AssetStudio.Plugin.Impl;

public class HoloearthLoader : FileLoader
{

    public override Stream ProcessFile(Stream file, string filename)
    {
        var name = Path.GetFileNameWithoutExtension(filename);
        var ext = Path.GetExtension(filename);
        var dec = Path.ChangeExtension(filename, $"decrypted.{ext}");

        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.KeySize = 128;
        aes.Key = DeriveKey(name, aes.KeySize / 8);
        aes.IV = new byte[16];
        using var encryptor = aes.CreateEncryptor();

        var buffer = new byte[file.Length];
        if (file.Read(buffer) == file.Length)
        {
            Decrypt(encryptor, buffer, 0, buffer.Length, aes.BlockSize / 8);
            return new MemoryStream(buffer);
        }

        throw new Exception();
    }

    public override bool CanProcessFile(Stream file, string filename)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.KeySize = 128;
        aes.Key = DeriveKey(Path.GetFileNameWithoutExtension(filename), aes.KeySize / 8);
        aes.IV = new byte[16];
        using var encryptor = aes.CreateEncryptor();

        var buffer = new byte[7];
        if (file.Read(buffer) == 7)
        {
            Decrypt(encryptor, buffer, 0, 7, aes.BlockSize / 8);
            return buffer.SequenceEqual("UnityFS"u8.ToArray());
        }

        return false;
    }

    private static void Decrypt(ICryptoTransform enc, byte[] buffer, int offset, int length, int blockSize)
    {
        var remainder = offset % blockSize;
        var quotient = offset / blockSize + 1;
        var transformBuffer = new byte[blockSize];
        var quotientBuffer = new byte[blockSize];
        while (offset < length)
        {
            if (remainder % blockSize == 0)
            {
                var bytes = BitConverter.GetBytes(quotient++);
                bytes.CopyTo(quotientBuffer, 0);
                enc.TransformBlock(quotientBuffer, 0, quotientBuffer.Length, transformBuffer, 0);
                remainder = 0;
            }
            buffer[offset++] ^= transformBuffer[remainder++];
        }
    }

    private static string Password = "a4886faf24895680f4af42ab802b3dc44d70e3aaccb26b9098d65fc8ff8d9184";

    private static byte[] DeriveKey(string filename, int length)
    {
        using var derive = new PasswordDeriveBytes(Password, Encoding.UTF8.GetBytes(filename));
        return derive.GetBytes(length);
    }
}