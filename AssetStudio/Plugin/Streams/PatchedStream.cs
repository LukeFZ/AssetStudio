using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AssetStudio.Plugin.Streams;

public class PatchedStream : ReadOnlyBaseStream
{
    private readonly List<(int Offset, byte[] Contents)> _patches;

    public PatchedStream(Stream baseStream, IEnumerable<(int Offset, byte[] Contents)> patches)
        : base(baseStream)
    {
        _patches = patches.ToList();
    }

    public override int Read(byte[] buffer, int offset, int count)
        => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        var count = (int)Math.Min(buffer.Length, _stream.Length - _stream.Position);
        if (count == 0)
            return 0;

        var remaining = count;
        var read = 0;
        while (remaining != 0)
        {
            var startPosition = _stream.Position;
            var endPosition = startPosition + remaining;

            var applicablePatch = _patches.LastOrDefault(x => startPosition >= x.Offset);
            if (applicablePatch != default)
            {
                var patchOffset = (int)(startPosition - applicablePatch.Offset);
                var patchCount = Math.Min(remaining, applicablePatch.Contents.Length - patchOffset);

                read += patchCount;
                remaining -= patchCount;
                _stream.Position += patchCount;

                applicablePatch.Contents.AsSpan(patchOffset, patchCount).CopyTo(buffer.Slice(read, patchCount));
                continue;
            }

            var nextApplicablePatch = _patches.FirstOrDefault(x => x.Offset > startPosition && endPosition > x.Offset);
            if (nextApplicablePatch != default)
            {
                var streamReadAmount = (int)(nextApplicablePatch.Offset - startPosition);
                _stream.CheckedRead(buffer.Slice(read, streamReadAmount));
                read += streamReadAmount;
                remaining -= streamReadAmount;
                continue;
            }

            _stream.CheckedRead(buffer.Slice(read, remaining));
            read += remaining;
            remaining -= remaining;
        }

        return read;
    }
}