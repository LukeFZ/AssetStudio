using System;
using System.Diagnostics;
using System.IO;
using K4os.Hash.xxHash;

namespace AssetStudio.Plugin.Impl;

file static class Extensions
{
    public static Span<byte> ToBigEndian(this uint val) => new[]
    {
        (byte) (val >> 24),
        (byte) (val >> 16),
        (byte) (val >> 8),
        (byte) val,
    };

    public static Span<byte> ToBigEndian(this ulong val) => new[]
    {
        (byte) (val >> 56),
        (byte) (val >> 48),
        (byte) (val >> 40),
        (byte) (val >> 32),
        (byte) (val >> 24),
        (byte) (val >> 16),
        (byte) (val >> 8),
        (byte) val,
    };
}

public class ShengquLoader : FileLoader
{
    public override bool CanProcessFile(Stream file, string filename)
    {
        var reader = new EndianBinaryReader(file);
        var hdr = reader.ReadStringToNull();
        return hdr == "SQGDNFS";
    }

    public override Stream ProcessFile(Stream file, string filename)
    {
        var reader = new EndianBinaryReader(file);
        reader.ReadStringToNull();

        var packedVersion = reader.ReadUInt32();

        var bundleVersion = packedVersion & 0xffff;
        var encryptionVersion = packedVersion >> 16;

        Debug.Assert(bundleVersion == 7 && encryptionVersion == 1);

        var totalLength = reader.ReadUInt64();

        var keyOffset = reader.ReadInt32();

        var sizes = (stackalloc byte[12]);
        sizes.Clear();

        var sizesInt = sizes.As<uint>();
        ReadSpan(sizesInt, reader.ReadUInt32);

        var key = (stackalloc byte[1024]);
        key.Clear();

        GenerateKey("SQGDNFS"u8, key);
        Decrypt(sizes, key, keyOffset);

        var compressedInfo = sizesInt[0];
        var uncompressedInfo = sizesInt[1];
        var flags = sizesInt[2];

        var blocksInfo = new byte[compressedInfo];
        reader.CheckedRead(blocksInfo);

        GenerateKey("q2xXocd2OdC5cfHCUN1FHgXGK48IgsH0"u8, key);

        Decrypt(blocksInfo, key, keyOffset);

        var ms = new MemoryStream(new byte[file.Length + 32]);

        ms.Write("UnityFS\0"u8);
        ms.Write(bundleVersion.ToBigEndian());
        ms.Write("5.x.x\0"u8);
        ms.Write("2019.4.40f1\0"u8);

        ms.Write(totalLength.ToBigEndian());
        ms.Write(compressedInfo.ToBigEndian());
        ms.Write(uncompressedInfo.ToBigEndian());
        ms.Write(flags.ToBigEndian());

        ms.AlignStream(16, true);

        ms.Write(blocksInfo);
        ms.Seek(0, SeekOrigin.Begin);


        var bundleReader = new EndianBinaryReader(ms);
        var bundle = new BundleFile();
        bundle.Initialize(bundleReader);
        bundle.ReadHeader(bundleReader);
        bundle.ReadBlocksInfoAndDirectory(bundleReader);

        for (int i = 0; i < bundle.m_BlocksInfo.Length; i++)
        {
            var blockInfo = bundle.m_BlocksInfo[i];
            var blk = BigArrayPool<byte>.Shared.Rent((int)blockInfo.compressedSize);
            var block = blk.AsSpan(0, (int)blockInfo.compressedSize);
            file.CheckedRead(block);
            if (i == 0)
            {
                Decrypt(block, key, keyOffset);
            }
            else
            {
                block.As<uint>()[0] ^= (uint)keyOffset;
            }
            ms.Write(block);
            BigArrayPool<byte>.Shared.Return(blk);
        }

        file.CopyTo(ms);

        ms.Seek(0, SeekOrigin.Begin);

        return ms;
    }

    private static readonly byte[] StaticKey = Convert.FromHexString("caf1fcf7fee8ecc6def8f4fceac6ced6ddc6d5dfc6caf8f5ed");

    private static void GenerateKey(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var staticKeySpan = StaticKey.AsSpan();

        var key = output.As<ulong>();
        Debug.Assert(key.Length == 128);

        var state = new XXH64();

        var currentVal = (ulong) (input.Length ^ staticKeySpan.Length);

        var staticOffset = 0;
        var inputOffset = 0;

        for (int i = 0; i < 128; i++)
        {
            state.Reset(currentVal);

            state.Update(
                (i & 1) != 0 
                    ? staticKeySpan[(staticOffset++ % staticKeySpan.Length)..] 
                    : input[(inputOffset++ % input.Length)..]);

            currentVal = state.Digest();

            key[i] = currentVal;
        }
    }

    private static void Decrypt(Span<byte> data, Span<byte> key, int keyOffset)
    {
        if (data.Length == 0)
            return;

        keyOffset &= key.Length - 8;

        for (int i = 0; i < data.Length; i++)
        {
            data[i] ^= key[(keyOffset + i) % key.Length];
        }
    }

    private static void ReadSpan<T>(Span<T> span, Func<T> readerFunc) where T : unmanaged
    {
        for (int i = 0; i < span.Length; i++)
            span[i] = readerFunc();
    }
}