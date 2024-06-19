using System.Diagnostics;
using System;
using System.Collections.Generic;
using System.IO;

namespace AssetStudio.Plugin.Impl;

file static class Extensions
{
    [DebuggerStepThrough] public static byte RotateLeft(this byte val, int count) => (byte)((val << count) | (val >> (8 - count)));
}

public class FairGuard2Loader : FileLoader
{
    public override Stream ProcessFile(Stream file, string filename)
    {
        var encInfo = GetEncryptedBlockData(file);
        if (encInfo == null)
            throw new UnreachableException();

        var (encBlock, encPos) = encInfo.Value;
        Decrypt(encBlock);

        var ms = new MemoryStream();
        file.Seek(0, SeekOrigin.Begin);
        file.CopyTo(ms);
        ms.Seek(encPos, SeekOrigin.Begin);
        ms.Write(encBlock);

        ms.Seek(0, SeekOrigin.Begin);

        return ms;
    }

    public override bool CanProcessFile(Stream file, string filename)
    {
        try
        {
            var encInfo = GetEncryptedBlockData(file);
            if (encInfo == null)
                return false;

            var (encData, _) = encInfo.Value;

            return encData != null && CanBeDecrypted(encData);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static (byte[] encData, long encPos)? GetEncryptedBlockData(Stream file)
    {
        var reader = new EndianBinaryReader(file);
        var bundle = new BundleFile();
        bundle.Initialize(reader);
        if (bundle.m_Header.signature != "UnityFS")
            return null;

        bundle.ReadHeader(reader);
        bundle.ReadBlocksInfoAndDirectory(reader);
        if (bundle.m_BlocksInfo.Length == 0)
            return null;

        var firstBlock = bundle.m_BlocksInfo[0];

        var encBlockSize = firstBlock.compressedSize < 0x500 ? firstBlock.compressedSize : 0x500;
        var encPos = reader.Position;
        return (reader.ReadBytes((int)encBlockSize), encPos);
    }

    private static bool CanBeDecrypted(Span<byte> encData)
    {
        if (32 > encData.Length) return false;

        return
            encData.Length >= 31
            // Crazy heuristic
            && encData[..4].Contains<byte>(0xa6);
    }

    public static void Decrypt(Span<byte> encData)
    {
        var encLength = (uint)encData.Length;
        var encDataInt = encData.As<uint>();

        for (int i = 0; i < 32; i++)
            encData[i] ^= 0xa6;

        if (encLength == 32)
            return;

        var encBlock1 = (stackalloc uint[5]);
        encBlock1[0] = encDataInt[2] ^ encDataInt[6] ^ 0x2D06211Fu;
        encBlock1[1] = encDataInt[3] ^ encDataInt[0] ^ encLength ^ 0xBE482704u;
        encBlock1[2] = encDataInt[1] ^ encDataInt[5] ^ encLength ^ 0x753BDCAAu;
        encBlock1[3] = encDataInt[0] ^ encDataInt[7] ^ 0x611C39EFu;
        encBlock1[4] = encDataInt[4] ^ encDataInt[7] ^ 0x6F2A7347u ^ 0x4736C714u;

        // Surprise tool for later :)
        var encBlock1Derived = (stackalloc byte[4]);
        GenerateKey(ref encBlock1, out encBlock1Derived);
        var encBlock1Crc = CustomCrc32.GetCrc32(encBlock1Derived) + 2;
        var encBlock1CrcBytes = (stackalloc byte[4]);
        encBlock1CrcBytes.As<uint>()[0] = encBlock1Crc;

        var encBlock1Key = 
            encDataInt[1] ^
            encDataInt[2] ^ 
            encDataInt[6] ^ 
            0x1274CBECu ^ 
            encDataInt[3] ^
            encDataInt[5] ^
            encLength ^ 
            encDataInt[4] ^
            0x6F2A7347u ^
            0xD22BEFA6u;

        var encBlockRc4 = new CustomRc4(kb => (byte)(kb.RotateLeft(1) - 0x61));
        encBlockRc4.Decrypt(encBlock1.AsBytes(), BitConverter.GetBytes(encBlock1Key));

        var decBlock1Crc = CustomCrc32.GetCrc32(encBlock1.AsBytes()) + 2;

        var crcKeyMaterial = (stackalloc uint[1]);
        crcKeyMaterial[0] = decBlock1Crc;

        var secondGenerated = (stackalloc byte[4]);
        GenerateKey(ref crcKeyMaterial, out secondGenerated);
        var secondGeneratedKey = secondGenerated.As<uint>()[0];

        var keyMaterial21 = (encBlock1[3] - 0x1C26B82Du) ^ secondGeneratedKey;
        var keyMaterial22 = (encBlock1[0] ^ 0x82C57E3C) ^ secondGeneratedKey;
        var keyMaterial23 = (encBlock1[1] + 0x6F2A7347) ^ encBlock1Crc;
        var keyMaterial24 = (encBlock1[2] + 0x3F72EAF3u) ^ encBlock1Crc;

        if (encLength - 32 < 0x80)
        {
            encBlockRc4.Decrypt(encData[32..], encBlock1CrcBytes);
            return;
        }

        var encBlock = encData.Slice(0x20, 0x60);
        encBlockRc4.Decrypt(encBlock, encBlock1CrcBytes);
        for (int i = 0; i < encBlock.Length; i++)
            encBlock[i] ^= (byte)(encBlock1Crc ^ 0x6e);

        var blockSize = (int)((encLength - 0x80) / 4);
        
        var roundKeys = (stackalloc uint[4]);
        roundKeys[0] = encBlock1Crc ^ keyMaterial21 ^ 0x6142756Eu;
        roundKeys[1] = encBlock1Crc ^ keyMaterial24 ^ 0x62496E66u;
        roundKeys[2] = encBlock1Crc ^ keyMaterial22 ^ 0x1304B000u;
        roundKeys[3] = encBlock1Crc ^ keyMaterial23 ^ 0x6E8E30ECu;

        for (int i = 0; i < 4; i++)
        {
            var current = encData.Slice(0x80 + i * blockSize, blockSize);
            encBlockRc4.Decrypt(current, encBlock1CrcBytes);
            for (int j = 0; j < blockSize / 4; j++)
                current.As<uint>()[j] ^= roundKeys[i];
        }
    }

    private static void GenerateKey(ref Span<uint> keyMaterial, out Span<byte> outKey)
    {
        var keyMaterialBytes = keyMaterial.AsBytes();

        var temp1 = 0x78DA0550u;
        var temp2 = 0x2947E56Bu;
        var key = 0xc1646153u;

        foreach (var byt in keyMaterialBytes)
        {
            key = 0x21 * key + byt;

            if ((key & 0xf) > 0xA)
            {
                var xor = 1u;
                if (temp2 >> 6 == 0)
                    xor = temp2 << 26 != 0 ? 1u : 0u;
                key = (key ^ xor) - 0x2CD86315;
            }
            else if ((byte)key >> 4 == 0xf)
            {
                var xor = 1u;
                if (temp2 >> 9 == 0)
                    xor = temp2 << 23 != 0 ? 1u : 0u;
                key = (key ^ xor) + (temp1 ^ 0xAB4A010B);
            }
            else if (((key >> 8) & 0xf) <= 1)
            {
                temp1 = key ^ ((temp2 >> 3) - 0x55eeab7b);
            }
            else if (temp1 + 0x567A > 0xAB5489E3)
            {
                temp1 = key ^ ((temp1 & 0xffff0000) >> 16);
            }
            else if ((temp1 ^ 0x738766FA) <= temp2)
            {
                temp1 = temp2 ^ (temp1 >> 8);
            }
            else if (temp1 == 0x68F53AA6)
            {
                if (((key + temp2) ^ 0x68F53AA6) > 0x594AF86E)
                    temp1 = 0x602B1178;
                else
                    temp2 -= 0x760A1649;
            }
            else
            {
                if (key <= 0x865703AF)
                    temp1 = key ^ (temp1 - 0x12B9DD92);
                else
                    temp1 = (key - 0x564389D7) ^ temp2;

                var xor = 1u;
                if (temp1 >> 8 == 0)
                    xor = temp1 << 24 != 0 ? 1u : 0u;
                key ^= xor;
            }
        }

        outKey = BitConverter.GetBytes(key).AsSpan();
    }
}

file class CustomRc4
{
    private readonly Func<byte, byte> _transform;

    public CustomRc4(Func<byte, byte> transform)
    {
        _transform = transform;
    }

    public void Decrypt(Span<byte> data, Span<byte> key)
    {
        if (data.Length <= 0)
            return;

        var kt = new byte[256];
        for (int i = 0; i < 256; i++)
            kt[i] = (byte)i;

        var swap = 0;
        for (int i = 0; i < 256; i++)
        {
            var a = kt[i];
            swap = (swap + a + key[i % key.Length]) & 0xff;
            kt[i] = kt[swap];
            kt[swap] = a;
        }

        byte j = 0, k = 0;
        for (int i = 0; i < data.Length; i++)
        {
            j++;
            var a = kt[j];
            k = (byte)(a + k);
            kt[j] = kt[k];
            kt[k] = a;

            var kb = kt[(byte)(a + kt[j])];
            data[i] ^= _transform(kb);
        }
    }
}

file static class CustomCrc32
{
    private static readonly uint[] Lookup = new uint[256];

    static CustomCrc32()
    {
        for (uint i = 0; i < 256; i++)
        {
            var val = i;
            for (uint j = 0; j < 8; j++)
            {
                if ((val & 1) == 0)
                    val >>= 1;
                else
                    val = (val >> 1) ^ 0xD35E417E;
            }

            Lookup[i] = val;
        }
    }

    public static uint GetCrc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xffffffffu;
        foreach (var byt in data)
        {
            crc = (Lookup[unchecked((byte)crc ^ byt)] ^ (crc >> 9)) + 0x5b;
        }

        return ~crc + 0xBE9F85C1;
    }
}