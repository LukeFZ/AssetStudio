using System;
using System.Buffers;
using System.IO;
using AssetStudio.Plugin.Streams;

namespace AssetStudio.Plugin.Impl;

// JewelPriLoader
public class FakeHeaderLoader : FileLoader
{
    public override int Priority => 10;

    public override Stream ProcessFile(Stream file, string filename)
    {
        var offset = FindOffset(file);
        return new OffsetStream(file, offset);
    }

    public override bool CanProcessFile(Stream file, string filename)
    {
        if (file.Length < 8) return false;
        return FindOffset(file) != -1;
    }

    private static int FindOffset(Stream file)
    {
        var buf = ArrayPool<byte>.Shared.Rent(0x250);

        file.Position = 1;
        var read = file.Read(buf, 0, 0x250);
        var offset = buf.AsSpan(0, read).LastIndexOf("UnityFS"u8);

        ArrayPool<byte>.Shared.Return(buf);

        return offset == -1 ? offset : offset + 1;
    }
}