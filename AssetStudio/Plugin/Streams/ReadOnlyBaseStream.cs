using System;
using System.IO;

namespace AssetStudio.Plugin.Streams;

public abstract class ReadOnlyBaseStream : NonWritableStream
{
    protected readonly Stream _stream;

    protected ReadOnlyBaseStream(Stream baseStream)
    {
        _stream = baseStream;
    }

    public override long Seek(long offset, SeekOrigin origin)
        => _stream.Seek(offset, origin);

    public override bool CanRead => _stream.CanRead;
    public override bool CanSeek => _stream.CanSeek;
    public override long Length => _stream.Length;

    public override long Position
    {
        get => _stream.Position;
        set => _stream.Position = value;
    }

    public override int Read(byte[] buffer, int offset, int count)
        => Read(buffer.AsSpan(offset, count));
}