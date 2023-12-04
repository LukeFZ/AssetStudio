using K4os.Compression.LZ4;
using System;
using System.IO;
using System.Linq;

namespace AssetStudio.Plugin.Impl;

public class OnePieceLoader : FakeHeaderLoader
{
    public override int Priority => 100;

    public override bool CanProcessFile(Stream file, string filename)
    {
        var version = "2018.4.13f1"u8;
        var buffer = (stackalloc byte[version.Length]);
        if (!file.CheckedRead(buffer) || !buffer.SequenceEqual(version))
            return false;

        file.Position += 7;
        return file.CheckedRead(buffer) && buffer.SequenceEqual(version);
    }

    public override Stream ProcessFile(Stream file, string filename)
    {
        var actualFile = base.ProcessFile(file, filename); // Get rid of fake header
        var reader = new EndianBinaryReader(actualFile);

        var bundle = new BundleFile();
        bundle.Initialize(reader);
        bundle.ReadHeader(reader);
        bundle.ReadBlocksInfoAndDirectory(reader);

        var blockStartPosition = reader.Position;

        var calculatedKey = -1;
        {
            var firstBlockInfo = bundle.m_BlocksInfo.First();
            var pos = reader.Position;
            var compressedSize = (int)firstBlockInfo.compressedSize;
            var compressedBytes = BigArrayPool<byte>.Shared.Rent(compressedSize);
            var uncompressedSize = (int)firstBlockInfo.uncompressedSize;
            var uncompressedBytes = BigArrayPool<byte>.Shared.Rent(uncompressedSize);

            for (int i = 0; i != 0x200; i++)
            {
                Array.Clear(uncompressedBytes);
                Array.Clear(compressedBytes);

                reader.Position = pos;
                reader.CheckedRead(compressedBytes, 0, compressedSize);

                Decrypt(compressedBytes.AsSpan(0, compressedSize), i);

                if (LZ4Codec.Decode(compressedBytes, 0, compressedSize, uncompressedBytes, 0, uncompressedSize) != -1)
                {
                    calculatedKey = i;
                    break;
                }
            }

            BigArrayPool<byte>.Shared.Return(compressedBytes);
            BigArrayPool<byte>.Shared.Return(uncompressedBytes);
        }

        actualFile.Position = 0;
        var data = new byte[actualFile.Length];
        actualFile.CheckedRead(data);

        var blockOffset = blockStartPosition;
        foreach (var blockInfo in bundle.m_BlocksInfo)
        {
            Decrypt(data.AsSpan((int)blockOffset, (int)blockInfo.compressedSize), calculatedKey);
            blockOffset += blockInfo.compressedSize;
        }

        return new MemoryStream(data);
    }

    private static void Decrypt(Span<byte> encrypted, int key)
    {
        switch (key)
        {
            case 0:
                return;
            case > 0x100:
            {
                var keyByte = (byte)(key - 0x100);
                for (int j = 0; j < encrypted.Length; j++)
                {
                    var xorPos = (j + encrypted.Length + (keyByte * keyByte)) % (j + 1);
                    (encrypted[j], encrypted[xorPos]) = (encrypted[xorPos], encrypted[j]);
                    encrypted[xorPos] ^= keyByte;
                    encrypted[j] ^= keyByte;
                }

                break;
            }
            default:
            {
                encrypted[0] ^= (byte)key;
                for (int j = 1; j < encrypted.Length; ++j)
                {
                    encrypted[j] ^= encrypted[j - 1];
                }

                break;
            }
        }
    }
}