using System;
using System.Diagnostics;
using K4os.Compression.LZ4;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace AssetStudio.Plugin.Impl;

public class NeteaseLoader : IFileLoader
{
    public Stream ProcessFile(Stream file, string filename)
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

    public bool CanProcessFile(Stream file, string filename)
    {
        try
        {
            var encInfo = GetEncryptedBlockData(file);
            if (encInfo == null)
                return false;

            var (encData, _) = encInfo.Value;

            return encData != null && (CanBeDecrypted1(encData) || GetObfuscatedVersionOffset(encData) != -1);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static (byte[] encData, long encPos)? GetEncryptedBlockData(Stream file)
    {
        var reader = new EndianBinaryReader(file);
        var unityFs = reader.ReadStringToNull();
        if (unityFs != "UnityFS")
            return null;

        var version = reader.ReadUInt32();
        var unityVer = reader.ReadStringToNull();
        var unityRev = reader.ReadStringToNull();

        var totalSize = reader.ReadInt64();
        var compressedBlocksInfoSize = reader.ReadUInt32();
        var uncompressedBlocksInfoSize = reader.ReadUInt32();
        var flags = (ArchiveFlags)reader.ReadUInt32();
        if (version >= 7)
        {
            reader.AlignStream(16);
        }

        var compressionType = (CompressionType)(flags & ArchiveFlags.CompressionTypeMask);
        if (compressionType != CompressionType.None && compressionType != CompressionType.Lz4HC)
        {
            // Not supported by netease
            return null;
        }

        var blocksInfo = reader.ReadBytes((int)compressedBlocksInfoSize);

        Stream blocksInfoStream;
        if (compressionType == CompressionType.Lz4HC)
        {
            var uncompressedBytes = new byte[uncompressedBlocksInfoSize];
            var numWrite = LZ4Codec.Decode(blocksInfo, uncompressedBytes);
            if (numWrite != uncompressedBlocksInfoSize)
            {
                throw new IOException($"Lz4 decompression error, write {numWrite} bytes but expected {uncompressedBlocksInfoSize} bytes");
            }
            blocksInfoStream = new MemoryStream(uncompressedBytes);
        }
        else
        {
            blocksInfoStream = new MemoryStream(blocksInfo);
        }

        using var blockInfoReader = new EndianBinaryReader(blocksInfoStream);
        blockInfoReader.ReadBytes(16);
        var blockCount = blockInfoReader.ReadInt32();
        var uncompressedBlockSize = blockInfoReader.ReadUInt32();
        var compressedBlockSize = blockInfoReader.ReadUInt32();

        var encBlockSize = compressedBlockSize < 0x1000 ? compressedBlockSize : 0x1000;
        var encPos = reader.Position;
        return (reader.ReadBytes((int)encBlockSize), encPos);
    }

    private static bool CanBeDecrypted1(byte[] enc)
    {
        if (enc.Length < 64)
            return false;

        var magic = BitConverter.ToUInt32(enc.AsSpan(0, 4));
        var magic2 = BitConverter.ToUInt32(enc.AsSpan(4, 4));

        if (magic is 0xAEA6A6FB or 0xA6A6A6FB)
            return true;

        if ((magic2 & 0xFFFFFF) == 0xA6A6A7)
            return true;

        for (int i = 0; i < 12; i++)
        {
            var val = BitConverter.ToUInt32(enc.AsSpan((i * 4)..(i * 4 + 4)));
            
            if (val is 0xA6B3A6A6 or 0xA6B7A6A6)
                return true;
        }

        return false;
    }

    private static int GetObfuscatedVersionOffset(byte[] enc) // Checks encryption of AssetBundleVersion 
    {
        if (enc.Length < 64)
            return -1;

        const uint check = 0x7e07;

        for (int i = 0; i < 64; i++)
        {
            var magic = BitConverter.ToUInt16(enc.AsSpan(i, 2));
            if (magic != 0xddee) continue;

            var packedUnityVerYear = BitConverter.ToUInt16(enc.AsSpan(i + 2, 2));
            if (packedUnityVerYear - 0x2017 > 0xe) continue;

            var bit = packedUnityVerYear - 0x2017;
            if ((check & 1 << bit) == 0) continue;
            return i;
        }

        return -1;
    }

    private static void Decrypt(byte[] enc)
    {
        var verOffset = GetObfuscatedVersionOffset(enc); // Offset after the encrypted year
        DecryptVersion(enc, verOffset);
        var encSectionOffset = (verOffset > 0x1f ? 0x10 : 0) + 0x30;
        DecryptData(enc, encSectionOffset);
    }

    private static void DecryptVersion(byte[] enc, int verOffset)
    {
        var packedUnityVerYear = BitConverter.ToUInt16(enc.AsSpan(verOffset + 2, 2));

        // This check only works for version 3 of the encryption.
        // We know the encrypted section length already, so this is skippable
        /*if (enc[verOffset + 4] == 0xaa && enc[verOffset + 4 + 2] == 0xbb)
            encSectionLength = 0x1000;
        else
        {
            encSectionLength = enc[verOffset + 4] * 0x10 + enc[verOffset + 4 + 2];
        }*/

        // Unpack unity year back to 4 bytes (21 20 -> 2021)
        enc[verOffset] = (byte)((packedUnityVerYear >> 12) & 0xf | 0x30);
        enc[verOffset + 1] = (byte)((packedUnityVerYear >> 8) & 0xf | 0x30);
        enc[verOffset + 2] = (byte)((packedUnityVerYear >> 4) & 0xf | 0x30);
        enc[verOffset + 3] = (byte)(packedUnityVerYear & 0xf | 0x30);


        // Only required for version 3, though it doesn't break v1 since there this isnt obfuscated
        enc[verOffset + 4] = 0x2e;
        enc[verOffset + 4 + 2] = 0x2e;
        if (enc[verOffset + 4 + 4] == verOffset)
            enc[verOffset + 4 + 4] = 0x66; // f
        if (enc[verOffset + 4 + 5] == verOffset)
            enc[verOffset + 4 + 5] = 0x66; // f
    }

    private static void DecryptData(Span<byte> enc, int encSectionOffset)
    {
        var actualEncryptedLength = (uint)(enc.Length - encSectionOffset);

        var crcInts = MemoryMarshal.Cast<byte, uint>(enc.Slice(encSectionOffset, 0x20)).ToArray();
        var crcBytes =
                BitConverter.GetBytes(crcInts[3])
                .Concat(BitConverter.GetBytes(crcInts[1]))
                .Concat(BitConverter.GetBytes(crcInts[4]))
                .Concat(BitConverter.GetBytes(actualEncryptedLength))
                .Concat(BitConverter.GetBytes(crcInts[2]))
                .ToArray();

        var crc = NeteaseCrc32.GetCrc32(crcBytes);

        // Decrypt the CRC'ed area
        for (int i = 0; i < 0x20; i++)
            enc[encSectionOffset + i] ^= 0xa6;

        // It's a surprise tool that will help us later!
        uint[] crcKey = {
            crc ^ crcInts[5] + 0x1985,
            crc ^ crcInts[7] + 0x1981,
            crc ^ actualEncryptedLength + 0x2013,
            crc ^ crcInts[6] + 0x2018
        };

        var actualEncryptedOffset = encSectionOffset + 0x20;
        if (actualEncryptedLength > 0x9f)
        {
            var keyBlock = enc.Slice(actualEncryptedOffset, 0x80).ToArray();
            var keyBlockInt = MemoryMarshal.Cast<byte, uint>(keyBlock);

            NeteaseRc4.Decrypt(enc.Slice(actualEncryptedOffset, 0x80), BitConverter.GetBytes(crc));

            var rc4Key2 = BitConverter.GetBytes(crcKey[2]); // Not actually the array reference but the same value
            NeteaseRc4.Decrypt(keyBlock, rc4Key2); // Because it was so fun the first time

            uint[] keyTable2 =
            {
                0x571u,
                crcKey[3],
                0x892u,
                0x750u,
                crcKey[0],
                crcKey[1],
                0x746u,
                crcKey[2],
                0x568u
            };

            var remainingEncSection = actualEncryptedLength - 0xa0;
            var remainingNonAligned = actualEncryptedLength - (remainingEncSection & 0xffffff80) - 0xa0;
            if (actualEncryptedLength >= 0x120)
            {
                var currentBlockOffset = actualEncryptedOffset + 0x80;
                for (int i = 0; i < remainingEncSection / 0x80; i++)
                {
                    var type = keyTable2[i % 9] & 3;

                    Func<uint, uint, uint> getValFunc = type switch
                    {
                        0 => (idx, keyBlockVal) => keyTable2[idx % 9] ^ keyBlockVal ^ (32u - idx),
                        1 => (idx, keyBlockVal) => crcKey[keyBlockVal & 3] ^ keyBlockVal,
                        2 => (idx, keyBlockVal) => crcKey[keyBlockVal & 3] ^ keyBlockVal ^ idx,
                        3 => (idx, keyBlockVal) => crcKey[keyTable2[idx % 9] & 3] ^ keyBlockVal ^ idx,
                        _ => throw new UnreachableException()
                    };

                    var currentBlockSpan = MemoryMarshal.Cast<byte, uint>(enc.Slice(currentBlockOffset, 0x80));

                    for (int j = 0; j < 32; j++)
                    {
                        var keyBlockVal = keyBlockInt[j];
                        var val = getValFunc((uint)j, keyBlockVal);
                        currentBlockSpan[j] ^= val;
                    }

                    currentBlockOffset += 0x80;
                }
            }

            if (remainingNonAligned > 0)
            {
                var totalRemainingOffset = encSectionOffset + actualEncryptedLength - remainingNonAligned;
                for (int i = 0; i < remainingNonAligned; i++)
                {
                    enc[(int)totalRemainingOffset + i] ^= (byte)(i ^ keyBlock[i & 0x7f] ^ (byte)(keyTable2[crcKey[i & 3] % 9] % 0xff));
                }
            }
        }
        else
        {
            NeteaseRc4.Decrypt(enc.Slice(actualEncryptedOffset, (int)actualEncryptedLength - 0x20), BitConverter.GetBytes(crc));
        }
    }

    public static class NeteaseCrc32
    {
        private static readonly uint[] Lookup = new uint[256];

        static NeteaseCrc32()
        {
            for (uint i = 0; i < 256; i++)
            {
                var val = i;
                for (uint j = 0; j < 8; j++)
                {
                    if ((val & 1) == 0)
                        val >>= 1;
                    else
                        val = (val >> 1) ^ 0x4c11eb7;
                }

                Lookup[i] = val;
            }
        }

        public static uint GetCrc32(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
                return 0x82D63B78;

            var xor = 0xffffffffu;
            var crc = 0u;
            foreach (var byt in data)
            {
                crc = Lookup[unchecked((byte)xor ^ byt)] ^ (xor >> 8);
                xor = crc + 16;
            }

            return 0x82D63B67 - crc;
        }
    }

    public class NeteaseRc4
    {
        private readonly byte _add;
        private readonly bool _rotateRight;

        private static readonly NeteaseRc4 Instance = new();

        public static void Decrypt(Span<byte> data, Span<byte> key)
            => Instance.DecryptSpan(data, key);

        public NeteaseRc4(byte add = 0x3a, bool rotateRight = false)
        {
            _add = add;
            _rotateRight = rotateRight;
        }

        public void DecryptSpan(Span<byte> data, Span<byte> key)
        {
            var kt = new byte[256];
            for (int i = 0; i < 256; i++)
                kt[i] = (byte)i;

            var swap = 0;
            for (int i = 0; i < 256; i++)
            {
                // No idea why they do it like this.. compare to normal rc4 and replace if equal
                var a = kt[i];
                var b = a + swap;
                var c = key[i & 3];
                var d = c + b + 0xff;
                var e = c + b;
                if (e >= 0)
                    d = e;
                swap = e - (d & 0xffff00);
                kt[i] = kt[swap];
                kt[swap] = a;
            }

            if (data.Length > 0)
            {
                byte j = 0, k = 0;
                for (int i = 0; i < data.Length; i++)
                {
                    j++;
                    var a = kt[j];
                    k = (byte)(a + k);
                    kt[j] = kt[k];
                    kt[k] = a;

                    uint kb = kt[(byte)(a + kt[j])];
                    var rot = _rotateRight ? (byte)((kb >> 6) | (kb << 2)) : (byte)((kb << 6) | (kb >> 2));
                    data[i] ^= (byte)(rot + _add);
                }
            }
        }
    }
}