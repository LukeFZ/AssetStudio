using System;
using System.IO;

namespace AssetStudio.Plugin.Streams;

public abstract class NonWritableStream : Stream
{
    public override bool CanWrite => false;

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
}