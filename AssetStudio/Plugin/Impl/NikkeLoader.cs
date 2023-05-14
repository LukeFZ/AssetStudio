using System.IO;
using System.Security.Cryptography;

namespace AssetStudio.Plugin.Impl;

public class NikkeLoader : IFileLoader
{
    public Stream ProcessFile(Stream file, string filename)
    {
        var reader = new EndianBinaryReader(file, EndianType.LittleEndian);
        var sig = reader.ReadStringToNull(4);
        var ver = reader.ReadUInt32();

        var headerLen = unchecked(reader.ReadInt16() + 100);
        var encryptionMode = unchecked(reader.ReadInt16() + 100);
        var keyLen = unchecked(reader.ReadInt16() + 100);
        var encryptedLength = unchecked(reader.ReadInt16() + 100);

        var key = reader.ReadBytes(keyLen);
        var iv = reader.ReadBytes(16);

        var sha = SHA256.Create();
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        var decryptor = aes.CreateDecryptor(sha.ComputeHash(key), iv);
        var decryptedHeader = decryptor.TransformFinalBlock(reader.ReadBytes(encryptedLength), 0, encryptedLength);

        var memStream = new MemoryStream();
        memStream.Write(decryptedHeader, 0, decryptedHeader.Length);
        file.CopyTo(memStream);
        memStream.Seek(0, SeekOrigin.Begin);

        return memStream;
    }

    public bool CanProcessFile(Stream file, string filename)
    {
        if (file.Length < 8) return false;

        var reader = new EndianBinaryReader(file, EndianType.LittleEndian);
        var sig = reader.ReadStringToNull(4);
        var ver = reader.ReadUInt32();
        if (sig != "NKAB" || ver != 1)
            return false;

        var headerLen = unchecked(reader.ReadInt16() + 100);
        var encryptionMode = unchecked(reader.ReadInt16() + 100);
        var keyLen = unchecked(reader.ReadInt16() + 100);
        var encryptedLength = unchecked(reader.ReadInt16() + 100);
        if (encryptionMode != 0)
            return false;

        var key = reader.ReadBytes(keyLen);
        var iv = reader.ReadBytes(16);
        return reader.Position == headerLen; // Otherwise broken header.
    }
}