using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace AssetStudio.Plugin.Impl;

// tired :(
// this is a pretty janky setup
public class FairGuardLoaders : FileLoader
{
    public override bool ReturnsBundleFile => true;

    public override bool CanProcessFile(Stream file, string filename)
    {
        try
        {
            var encInfo = GetEncryptedBlockData(file);
            if (encInfo == null)
                return false;

            var (encData, _) = encInfo.Value;

            return encData != null && CanBeDecrypted(encData, out _);
        }
        catch (Exception)
        {
            return false;
        }
    }

    public override BundleFile ProcessBundle(FileReader reader)
    {
        var encInfo = GetEncryptedBlockData(reader.BaseStream);
        if (encInfo == null)
            throw new UnreachableException();

        var (encBlock, encPos) = encInfo.Value;

        var ms = new MemoryStream();
        reader.BaseStream.Seek(0, SeekOrigin.Begin);
        reader.BaseStream.CopyTo(ms);

        if (CanBeDecrypted(encBlock, out var isVersion1) && isVersion1)
        {
            DecryptV1(encBlock);

            ms.Seek(encPos, SeekOrigin.Begin);
            ms.Write(encBlock);

            ms.Seek(0, SeekOrigin.Begin);

            return BundleFile.Create(new FileReader(reader.FullPath, ms));
        }

        for (int i = 0; i < 2; i++)
        {
            var copy = encBlock.AsSpan().ToArray();

            switch (i)
            {
                case 0:
                    DecryptV2(copy);
                    break;
                case 1:
                    DecryptV3(copy);
                    break;
                default:
                    throw new UnreachableException();
            }

            ms.Seek(encPos, SeekOrigin.Begin);
            ms.Write(copy);

            ms.Seek(0, SeekOrigin.Begin);

            try
            {
                var bundle = BundleFile.Create(new FileReader(reader.FullPath, ms));
                return bundle;
            }
            catch (Exception)
            {
                // ignore
            }
        }

        throw new InvalidOperationException("Failed to decrypt bundle with any of the known FairGuard variations.");
    }

    public static void DecryptV1(Span<byte> encData) => DecryptOld(encData);

    public static void DecryptV2(Span<byte> encData) => DecryptNew(encData, [
        0x2D06211Fu,
        0xBE482704u,
        0x753BDCAAu,
        0x611C39EFu,
        0x281CB453u
    ]);

    public static void DecryptV3(Span<byte> encData) => DecryptNew(encData, [
        0x226a61b9u,
        0x7a39d018u,
        0x18f6d8aau,
        0xaa255fb1u,
        0xf78dd8ebu
    ]);

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

        var encBlockSize = Math.Min(firstBlock.compressedSize, 0x500);
        var encPos = reader.Position;
        return (reader.ReadBytes((int)encBlockSize), encPos);
    }

    private static bool CanBeDecrypted(Span<byte> encData, out bool isVersion1)
    {
        isVersion1 = false;
        if (32 > encData.Length) return false;

        var headerBytes = encData[..4];
        isVersion1 = headerBytes.Contains<byte>(0xb7);

        return isVersion1 || headerBytes.Contains<byte>(0xa6);
    }

    private static void DecryptNew(Span<byte> encData, ReadOnlySpan<uint> xorConstants)
    {
        Debug.Assert(xorConstants.Length == 5);

        var encLength = (uint)encData.Length;
        var remainingData = encData;

        var encDataInt = remainingData.As<uint>();

        for (int i = 0; i < 32; i++)
            remainingData[i] ^= 0xa6;

        remainingData = remainingData[0x20..];
        if (remainingData.Length == 0)
            return;

        var encBlock1 = (stackalloc uint[5]);
        encBlock1[0] = encDataInt[2] ^ encDataInt[6] ^ xorConstants[0];
        encBlock1[1] = encDataInt[3] ^ encDataInt[0] ^ xorConstants[1] ^ encLength;
        encBlock1[2] = encDataInt[1] ^ encDataInt[5] ^ xorConstants[2] ^ encLength;
        encBlock1[3] = encDataInt[0] ^ encDataInt[7] ^ xorConstants[3];
        encBlock1[4] = encDataInt[4] ^ encDataInt[7] ^ xorConstants[4];

        // Surprise tool for later :)
        var encBlock1Derived = (stackalloc byte[4]);
        DeriveKey(encBlock1, encBlock1Derived);
        var encBlock1Crc = CustomCrc32.GetCrc32(encBlock1Derived) + 2;
        var encBlock1CrcBytes = (stackalloc byte[4]);
        encBlock1CrcBytes.As<uint>()[0] = encBlock1Crc;

        var encBlockRc4 = new CustomRc4(kb => (byte)(byte.RotateLeft(kb, 1) - 0x61));
        if (0x80 > remainingData.Length)
        {
            encBlockRc4.Decrypt(remainingData, encBlock1CrcBytes);
        }
        else
        {
            var encBlock1Key =
                encBlock1[0] ^ encBlock1[1] ^ encBlock1[2] ^ encBlock1[3] ^ encBlock1[4] ^ encLength;

            encBlockRc4.Decrypt(encBlock1.AsBytes(), BitConverter.GetBytes(encBlock1Key));

            var decBlock1Crc = CustomCrc32.GetCrc32(encBlock1.AsBytes()) + 2;

            var crcKeyMaterial = (stackalloc uint[1]);
            crcKeyMaterial[0] = decBlock1Crc;

            var secondGenerated = (stackalloc byte[4]);
            DeriveKey(crcKeyMaterial, secondGenerated);
            var secondGeneratedKey = secondGenerated.As<uint>()[0];

            var keyMaterial21 = (encBlock1[3] - 0x1C26B82Du) ^ secondGeneratedKey;
            var keyMaterial22 = (encBlock1[0] ^ 0x82C57E3C) ^ secondGeneratedKey;
            var keyMaterial23 = (encBlock1[1] + 0x6F2A7347) ^ encBlock1Crc;
            var keyMaterial24 = (encBlock1[2] + 0x3F72EAF3u) ^ encBlock1Crc;

            var encBlock = remainingData[..0x60];
            encBlockRc4.Decrypt(encBlock, encBlock1CrcBytes);
            for (int i = 0; i < encBlock.Length; i++)
                encBlock[i] ^= (byte)(encBlock1Crc ^ 0x6e);

            remainingData = remainingData[0x60..];

            var blockSize = remainingData.Length / 4;

            var roundKeys = (stackalloc uint[4]);
            roundKeys[0] = encBlock1Crc ^ keyMaterial21 ^ 0x6142756Eu;
            roundKeys[1] = encBlock1Crc ^ keyMaterial24 ^ 0x62496E66u;
            roundKeys[2] = encBlock1Crc ^ keyMaterial22 ^ 0x1304B000u;
            roundKeys[3] = encBlock1Crc ^ keyMaterial23 ^ 0x6E8E30ECu;

            for (int i = 0; i < 4; i++)
            {
                var current = remainingData.Slice(i * blockSize, blockSize);
                encBlockRc4.Decrypt(current, encBlock1CrcBytes);

                var currentUint = current.As<uint>();
                for (int j = 0; j < currentUint.Length; j++)
                    currentUint[j] ^= roundKeys[i];
            }
        }
    }

    private static void DecryptOld(Span<byte> encData)
    {
        var encLength = encData.Length;

        var encDataInt = encData.As<uint>();

        var encBlock1 = (stackalloc uint[4]);
        encBlock1[0] = encDataInt[2] ^ encDataInt[5] ^ 0x3F72EAF3u;
        encBlock1[1] = encDataInt[3] ^ encDataInt[7] ^ (uint)encLength;
        encBlock1[2] = encDataInt[1] ^ encDataInt[4] ^ (uint)encLength ^ 0x753BDCAAu;
        encBlock1[3] = encDataInt[0] ^ encDataInt[6] ^ 0xE3D947D3u;

        // Surprise tool for later :)
        var encBlock2Key = (stackalloc byte[4]);
        DeriveKey(encBlock1, encBlock2Key);
        var encBlock2KeyInt = encBlock2Key.As<uint>()[0];

        var encBlock1Key = (uint)encLength ^ encBlock1[0] ^ encBlock1[1] ^ encBlock1[2] ^ encBlock1[3] ^ 0x5E8BC918u;

        var encBlockRc4 = new CustomRc4(kb => (byte)(byte.RotateLeft(kb, 1) - 0x61));
        encBlockRc4.Decrypt(encBlock1.AsBytes(), BitConverter.GetBytes(encBlock1Key));

        var crc = CustomCrc32.GetCrc32(encBlock1.AsBytes());

        for (int i = 0; i < 32; i++)
            encData[i] ^= 0xb7;

        if (encLength == 32)
            return;

        if (encLength < 0x9f)
        {
            encBlockRc4.Decrypt(encData[32..], encBlock2Key);
            return;
        }

        var keyMaterial2 = (stackalloc uint[4]);
        keyMaterial2[0] = (encBlock1[3] + 0x6F1A36D8u) ^ (crc + 0x2);
        keyMaterial2[1] = (encBlock1[2] - 0x7E9A2C76u) ^ encBlock2KeyInt;
        keyMaterial2[2] = encBlock1[0] ^ 0x840CF7D0u ^ (crc + 0x2);
        keyMaterial2[3] = (encBlock1[1] + 0x48D0E844) ^ encBlock2KeyInt;

        var keyBlockKey = (stackalloc byte[4]);
        DeriveKey(keyMaterial2, keyBlockKey);

        var encBlock2 = encData.Slice(0x20, 0x80);
        var keyBlock = encBlock2.ToArray().AsSpan();
        var keyBlockInt = keyBlock.As<uint>();

        encBlockRc4.Decrypt(keyBlock, keyBlockKey);
        encBlockRc4.Decrypt(encBlock2, keyMaterial2.AsBytes()[..12]);

        var keyTable2 = (stackalloc uint[9]);
        keyTable2[0] = 0x88558046u;
        keyTable2[1] = keyMaterial2[3];
        keyTable2[2] = 0x5C7782C2u;
        keyTable2[3] = 0x38922E17u;
        keyTable2[4] = keyMaterial2[0];
        keyTable2[5] = keyMaterial2[1];
        keyTable2[6] = 0x44B38670u;
        keyTable2[7] = keyMaterial2[2];
        keyTable2[8] = 0x6B07A514u;

        var encBlock3 = encData[0xa0..];
        var remainingEncSection = encLength - 0xa0;
        var remainingNonAligned = encLength - (remainingEncSection & 0xffffff80) - 0xa0;
        if (encLength >= 0x120)
        {
            const int blockSize = 0x20;
            for (int i = 0; i < remainingEncSection / 0x80; i++)
            {
                var currentBlockSlice = encBlock3.Slice(i * blockSize * 0x4, blockSize * 0x4).As<uint>();
                var type = keyTable2[i % 9] & 3;

                for (int idx = 0; idx < blockSize; idx++)
                {
                    var keyBlockVal = keyBlockInt[idx];
                    var val = type switch
                    {
                        0 => keyBlockVal ^ keyTable2[(int)(keyMaterial2[idx & 3] % 9)] ^ (uint)(blockSize - idx),
                        1 => keyBlockVal ^ keyMaterial2[(int)(keyBlockVal & 3)] ^ keyTable2[(int)(keyBlockVal % 9)],
                        2 => keyBlockVal ^ keyMaterial2[(int)(keyBlockVal & 3)] ^ (uint)idx,
                        3 => keyBlockVal ^ keyMaterial2[(int)(keyTable2[idx % 9] & 3)] ^ (uint)(blockSize - idx),
                        _ => throw new UnreachableException()
                    };

                    currentBlockSlice[idx] ^= val;
                }
            }
        }

        if (remainingNonAligned > 0)
        {
            var totalRemainingOffset = remainingEncSection - remainingNonAligned;
            for (int i = 0; i < remainingNonAligned; i++)
            {
                encBlock3[(int)totalRemainingOffset + i] ^= (byte)(i ^ keyBlock[i & 0x7f] ^ (byte)(keyTable2[(int)(keyMaterial2[i & 3] % 9)] % 0xff));
            }
        }
    }

    // Used for V2 and V3
    private static void DeriveKey(ReadOnlySpan<uint> keyMaterial, Span<byte> outKey)
    {
        var keyMaterialBytes = MemoryMarshal.AsBytes(keyMaterial);

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

        BitConverter.GetBytes(key).CopyTo(outKey);
    }
}

file class CustomRc4(Func<byte, byte> transform)
{
    private readonly Func<byte, byte> _transform = transform;

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