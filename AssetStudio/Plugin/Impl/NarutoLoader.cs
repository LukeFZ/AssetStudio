using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace AssetStudio.Plugin.Impl;

file static class Extensions
{
    public static void Xor(this Span<byte> data, ReadOnlySpan<byte> key)
    {
        var remaining = data.Length;
        var processed = 0;

        if (key.Length >= 8 && remaining >= 8)
        {
            var dataULong = data.As<ulong>();
            var keyULong = key.As<ulong>();

            var dataULongCount = dataULong.Length;
            var keyULongCount = keyULong.Length;
            for (int i = 0; i < dataULongCount; i++)
            {
                dataULong[i] ^= keyULong[i % keyULongCount];
            }

            var totalProcessed = dataULongCount * sizeof(ulong);
            processed += totalProcessed;
            remaining -= totalProcessed;
        }

        if (remaining > 0)
        {
            for (int i = processed; i < data.Length; i++)
            {
                data[i] ^= key[i % key.Length];
            }
        }
    }
}

public class NarutoLoader : FileLoader
{
    private static readonly Dictionary<string, int> MagicVersionMap = new()
    {
        ["UnityKHFS"] = 0,
        ["UnityKHNFS"] = 1,
        ["UnityKH1FS"] = 2
    };

    public override Stream ProcessFile(Stream file, string filename)
    {
        var reader = new EndianBinaryReader(file);
        var magic = reader.ReadStringToNull(11);
        var encVersion = MagicVersionMap[magic];
        file.Seek(-1, SeekOrigin.Current);

        var headerData = (stackalloc byte[0x1f]);
        file.CheckedRead(headerData);

        var blocksSizeBytes = (stackalloc byte[0xc]);
        file.CheckedRead(blocksSizeBytes);

        var blocksSize = BinaryPrimitives.ReadUInt32BigEndian(blocksSizeBytes);

        file.Seek(encVersion == 0 ? 0xc : 0xb, SeekOrigin.Current);

        var blocks = new byte[blocksSize];
        file.CheckedRead(blocks);

        var encSpan = blocks.AsSpan();

        var bigEndianBlocksSize = (stackalloc byte[8]);
        BinaryPrimitives.WriteUInt64BigEndian(bigEndianBlocksSize, blocksSize);

        switch (encVersion)
        {
            case 0:
                encSpan.Xor(GetKey(encVersion));
                break;
            case 1:
                encSpan.Xor(GetKey(encVersion));
                encSpan.Xor(bigEndianBlocksSize);
                break;
            case 2:
                var alignedLength = (encSpan.Length % 7 + 7) % encSpan.Length;
                Version2Transform(encSpan, 0, encSpan.Length, alignedLength);

                var currentKey = GetKey(blocksSize % 3 == 0 || blocksSize % 5 == 0 || blocksSize % 7 == 0 ? 1 : 0);
                encSpan.Xor(currentKey);
                encSpan.Xor(bigEndianBlocksSize);

                var endOffset = (encSpan.Length % 7 + 1) % alignedLength;
                for (int i = 0; i < encSpan.Length; i += alignedLength)
                    Version2Transform(encSpan, i, alignedLength, endOffset);

                Version2Transform(encSpan, 0, encSpan.Length, endOffset);
                break;
        }

        var zeroSpan = (stackalloc byte[0xe]);
        zeroSpan.Clear();

        var ms = new MemoryStream();
        ms.Write("UnityFS"u8);
        ms.Write(headerData);
        ms.Write(blocksSizeBytes);
        ms.Write(zeroSpan);
        ms.Write(encSpan);
        file.CopyTo(ms);

        ms.Seek(0, SeekOrigin.Begin);

        return ms;
    }

    public override bool CanProcessFile(Stream file, string filename)
    {
        var reader = new EndianBinaryReader(file);
        var magic = reader.ReadStringToNull(10);
        return MagicVersionMap.ContainsKey(magic);
    }

    private static ReadOnlySpan<byte> GetKey(int keyIndex)
    {
        return keyIndex switch
        {
            0 => "X@85Pq!6v$lCt7UYsihH3!cPb1P71bo4lX59FXqY!VO$YiYsu!Keu3aVZwi5on5l"u8,
            1 => "hAi5luE8FlyblDdCTQC9uxnj3rkNwd1swrKI7Mx1aDFEe2B5h#3X&s54%GuSeHf@"u8,
            _ => throw new UnreachableException()
        };
    }

    private static void Version2Transform(Span<byte> data, int offset, int length, int shiftCount)
    {
        var lastValidDataIndex = data.Length - 1;

        offset = Math.Min(lastValidDataIndex, offset);
        var endOffset = Math.Min(lastValidDataIndex, offset - 1 + length);
        length = endOffset - offset + 1;

        if (2 > length)
            return;

        var offsetInShift = shiftCount % length;
        if (offsetInShift == 0)
            return;

        var shiftedEndOffset = endOffset - offsetInShift;

        shiftedEndOffset = Math.Min(Math.Max(shiftedEndOffset, offset), endOffset);

        Swap(data, offset, Math.Min(lastValidDataIndex, shiftedEndOffset));
        Swap(data, Math.Min(lastValidDataIndex, shiftedEndOffset + 1), endOffset);
        Swap(data, offset, endOffset);

        return;

        static void Swap(Span<byte> data, int start, int end)
        {
            while (end > start)
            {
                (data[end], data[start]) = (data[start], data[end]);
                start++;
                end--;
            }
        }
    }
}