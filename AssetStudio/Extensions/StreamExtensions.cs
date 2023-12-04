using System.Diagnostics;
using System;
using System.IO;

namespace AssetStudio
{
    public static class StreamExtensions
    {
        private const int BufferSize = 81920;

        public static void CopyTo(this Stream source, Stream destination, long size)
        {
            var buffer = new byte[BufferSize];
            for (var left = size; left > 0; left -= BufferSize)
            {
                int toRead = BufferSize < left ? BufferSize : (int)left;
                int read = source.Read(buffer, 0, toRead);
                destination.Write(buffer, 0, read);
                if (read != toRead)
                {
                    return;
                }
            }
        }

        public static bool CheckedRead(this Stream stream, Span<byte> data)
        {
            var read = stream.Read(data);
            Debug.Assert(read == data.Length, "read == data.Length");
            return read == data.Length;
        }

        public static bool CheckedRead(this Stream stream, byte[] data, int index, int count)
        {
            var read = stream.Read(data, index, count);
            Debug.Assert(read == count, "read == count");
            return read == count;
        }

        public static void AlignStream(this Stream stream, int alignment, bool write = false)
        {
            var pos = stream.Position;
            var mod = pos % alignment;
            if (mod != 0)
            {
                var cnt = alignment - mod;

                if (write)
                {
                    stream.Write(new byte[cnt]);
                }
                else
                {
                    stream.Position += cnt;
                }
            }
        }
    }
}
