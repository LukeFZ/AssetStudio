using System;
using System.Buffers.Binary;
using System.IO;

namespace AssetStudio.Plugin.Impl;

public class NarutoLoader : FileLoader
{
    public override Stream ProcessFile(Stream file, string filename)
    {
        var reader = new EndianBinaryReader(file);
        var magic = reader.ReadStringToNull(11);
        var isOldFormat = magic == "UnityKHFS";
        file.Seek(-1, SeekOrigin.Current);

        var headerData = (stackalloc byte[0x1f]);
        file.CheckedRead(headerData);

        var blocksSizeBytes = (stackalloc byte[0xc]);
        file.CheckedRead(blocksSizeBytes);

        var blocksSize = BinaryPrimitives.ReadUInt32BigEndian(blocksSizeBytes);

        file.Seek(isOldFormat ? 0xc : 0xb, SeekOrigin.Current);

        var blocks = new byte[blocksSize];
        file.CheckedRead(blocks);

        var key = isOldFormat
            ? "X@85Pq!6v$lCt7UYsihH3!cPb1P71bo4lX59FXqY!VO$YiYsu!Keu3aVZwi5on5l"u8 
            : "hAi5luE8FlyblDdCTQC9uxnj3rkNwd1swrKI7Mx1aDFEe2B5h#3X&s54%GuSeHf@"u8; // UnityKHNFS

        var encSpan = blocks.AsSpan();

        var ulongCount = blocks.Length / 8;
        var rem = blocks.Length - ulongCount * 8;
        for (int i = 0; i < ulongCount; i++)
        {
            encSpan.As<ulong>()[i] ^= key.As<ulong>()[i % (key.Length / 8)];
        }

        if (rem > 0)
        {
            for (int i = ulongCount * 8; i < blocks.Length; i++)
            {
                encSpan[i] ^= key[i % key.Length];
            }
        }

        if (!isOldFormat)
        {
            var secondKey = (stackalloc byte[8]);
            BinaryPrimitives.WriteUInt64BigEndian(secondKey, blocksSize);

            for (int i = 0; i < ulongCount; i++)
            {
                encSpan.As<ulong>()[i] ^= secondKey.As<ulong>()[0];
            }

            if (rem > 0)
            {
                for (int i = ulongCount * 8; i < blocks.Length; i++)
                {
                    encSpan[i] ^= secondKey[i % secondKey.Length];
                }
            }
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
        return magic is "UnityKHFS" or "UnityKHNFS";
    }
}