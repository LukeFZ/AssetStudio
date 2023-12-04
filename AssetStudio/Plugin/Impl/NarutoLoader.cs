using System;
using System.Buffers.Binary;
using System.IO;

namespace AssetStudio.Plugin.Impl;

public class NarutoLoader : FileLoader
{
    public override Stream ProcessFile(Stream file, string filename)
    {
        file.Seek(9, SeekOrigin.Current);
        var headerData = (stackalloc byte[0x1f]);
        file.CheckedRead(headerData);

        var blocksSizeBytes = (stackalloc byte[0xc]);
        file.CheckedRead(blocksSizeBytes);

        var blocksSize = BinaryPrimitives.ReadUInt32BigEndian(blocksSizeBytes);

        file.Seek(0xc, SeekOrigin.Current);

        var blocks = new byte[blocksSize];
        file.CheckedRead(blocks);

        var key = "X@85Pq!6v$lCt7UYsihH3!cPb1P71bo4lX59FXqY!VO$YiYsu!Keu3aVZwi5on5l"u8;

        var encSpan = blocks.AsSpan();

        var ulongCount = blocks.Length / 8;
        for (int i = 0; i < ulongCount; i++)
        {
            encSpan.As<ulong>()[i] ^= key.As<ulong>()[i % 8];
        }

        var rem = blocks.Length - ulongCount * 8;
        if (rem > 0)
        {
            for (int i = ulongCount * 8; i < blocks.Length; i++)
            {
                encSpan[i] ^= key[i % 0x40];
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
        return reader.ReadStringToNull(9) == "UnityKHFS";
    }
}