using System;
using System.IO;

namespace AssetStudio.Plugin;

public class OffsetStream : Stream
{
    private readonly Stream _stream;
    private readonly long _offset;

    public OffsetStream(Stream stream, int offset = -1)
    {
        _stream = stream;

        if (offset != -1)
            _stream.Position = offset;

        _offset = _stream.Position;
    }

    public override int Read(byte[] buffer, int offset, int count)
        => _stream.Read(buffer, offset, count);

    public override long Seek(long offset, SeekOrigin origin)
    {
        return origin == SeekOrigin.Begin 
            ? _stream.Seek(_offset + offset, origin) 
            : _stream.Seek(offset, origin);
    }

    public override void Flush()
    {
        throw new NotImplementedException();
    }

    public override void SetLength(long value)
    {
        throw new NotImplementedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotImplementedException();
    }

    public override bool CanRead => _stream.CanRead;
    public override bool CanSeek => _stream.CanSeek;
    public override bool CanWrite => false;
    public override long Length => _stream.Length - _offset;
    public override long Position
    {
        get => _stream.Position - _offset;
        set => _stream.Position = value + _offset;
    }
}