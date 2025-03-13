#nullable enable
using System;
using System.Buffers.Binary;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace AssetStudio.Plugin.Impl;

public class IsekaiLoader : FileLoader
{
    private static readonly byte[] Key = Convert.FromHexString("756435d0a70456de6b0bedab2618fded");
    private static readonly byte[] Iv = Convert.FromHexString("0956af8ef1f83b082579564d80e36534");
    private static byte[] _cachedKeystream = [];
    private static Aes? _cipher;

    private static void EnsureKeystreamAvailable(int length)
    {
        if (_cachedKeystream.Length >= length)
            return;

        if (_cipher == null)
        {
            var cipher = Aes.Create();
            cipher.Key = Key;
            _cipher = cipher;
        }

        var blockCount = (length + 15) / 16;
        var currentIndex = _cachedKeystream.Length / 16;

        var block = (stackalloc byte[16]);
        var countBlock = (stackalloc byte[4]);

        var currentOffset = _cachedKeystream.Length;
        Array.Resize(ref _cachedKeystream, blockCount * 16);

        for (int i = currentIndex; i < blockCount; i++)
        {
            BinaryPrimitives.WriteInt32BigEndian(countBlock, currentIndex);
            Iv.CopyTo(block);

            MemoryMarshal.Cast<byte, uint>(block)[^1] ^= MemoryMarshal.Cast<byte, uint>(countBlock)[0];
            _cipher.EncryptEcb(block, _cachedKeystream.AsSpan(currentOffset, 16), PaddingMode.None);

            currentOffset += 16;
            currentIndex++;
        }
    }

    private static void XorData(Span<byte> data)
    {
        EnsureKeystreamAvailable(data.Length);
        for (int i = 0; i < data.Length; i++)
            data[i] ^= _cachedKeystream[i];
    }

    public override bool CanProcessFile(Stream file, string filename)
    {
        var header = (stackalloc byte[7]);
        file.ReadExactly(header);
        XorData(header);
        return header.SequenceEqual("UnityFS"u8);
    }

    public override Stream ProcessFile(Stream file, string filename)
    {
        var data = new byte[file.Length];
        file.ReadExactly(data);
        XorData(data);
        return new MemoryStream(data);
    }
}