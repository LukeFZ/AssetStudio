using AssetStudio.Plugin.Streams;
using System;
using System.Diagnostics;
using System.IO;

namespace AssetStudio.Plugin.Impl;

public class SingleByteXorLoader : FileLoader
{
    public override int Priority => 5;

    public override bool CanProcessFile(Stream file, string filename)
    {
        if (8 > file.Length)
            return false;

        var buffer = (stackalloc byte[8]);
        file.CheckedRead(buffer);
        buffer.As<ulong>()[0] ^= "UnityFS\0"u8.As<ulong>()[0];

        return buffer.IndexOfAnyExcept(buffer[0]) == -1 && buffer[0] != 0;
    }

    public override Stream ProcessFile(Stream file, string filename)
    {
        var first = file.ReadByte();
        Debug.Assert(first != -1);

        file.Seek(-1, SeekOrigin.Current);

        return new XorStream(file, (byte)(first ^ 0x55));
    }
}