using System;
using System.IO;

namespace AssetStudio.Plugin.Streams;

public class OffsetStream : ReadOnlyBaseStream
{
    private readonly long _offset;

    public OffsetStream(Stream stream, int offset = -1) : base(stream)
    {
        if (offset != -1)
            _stream.Position = offset;

        _offset = _stream.Position;
    }

    public override int Read(byte[] buffer, int offset, int count)
        => _stream.Read(buffer, offset, count);

    public override int Read(Span<byte> buffer)
        => _stream.Read(buffer);

    public override long Seek(long offset, SeekOrigin origin)
    {
        return origin == SeekOrigin.Begin
            ? _stream.Seek(_offset + offset, origin)
            : _stream.Seek(offset, origin);
    }

    public override long Length => _stream.Length - _offset;
    public override long Position
    {
        get => _stream.Position - _offset;
        set => _stream.Position = value + _offset;
    }
}