using System;
using System.IO;

namespace AssetStudio.Plugin.Streams;

public class XorStream : ReadOnlyBaseStream
{
    private readonly byte _xorKey;

    public XorStream(Stream baseStream, byte xorKey) : base(baseStream)
    {
        _xorKey = xorKey;
    }

    public override int Read(Span<byte> buffer)
    {
        var res = _stream.Read(buffer);
        for (int i = 0; i < res; i++)
        {
            buffer[i] ^= _xorKey;
        }
        return res;
    }
}