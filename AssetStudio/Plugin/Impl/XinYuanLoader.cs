using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace AssetStudio.Plugin.Impl;

public class XinYuanLoader : FileLoader
{
    public override Stream ProcessFile(Stream file, string filename)
    {
        file.Seek(7, SeekOrigin.Begin);

        var header = (stackalloc byte[9]);
        var readCount = file.Read(header);
        Debug.Assert(readCount == header.Length, "readCount == header.Length");

        Rc4.Decrypt(ref header);

        var blockSize = 1 << header[0];
        var totalLength = MemoryMarshal.Cast<byte, long>(header[1..])[0];

        var decryptedStream = new MemoryStream(new byte[totalLength]);

        var blockBuffer = (stackalloc byte[blockSize]);

        // Tiny speed improvement - since the key is constant for each block, precompute it here so we just need to do the xor
        var xorBuffer = (stackalloc byte[blockSize]);
        Rc4.Decrypt(ref xorBuffer);

        var remaining = totalLength;

        while (remaining > 0)
        {
            var currentLength = remaining > blockSize ? blockSize : (int)remaining;
            var currentBlock = blockBuffer[..currentLength];

            remaining -= currentLength;
            readCount = file.Read(currentBlock);
            Debug.Assert(readCount == currentBlock.Length, "readCount == currentBlock.Length");

            for (int i = 0; i < currentBlock.Length; i++)
            {
                currentBlock[i] ^= xorBuffer[i];
            }

            decryptedStream.Write(currentBlock);
        }

        decryptedStream.Seek(0, SeekOrigin.Begin);
        return decryptedStream;
    }

    public override bool CanProcessFile(Stream file, string filename)
    {
        var magic = (stackalloc byte[7]);
        return file.Read(magic) == 7 && Encoding.UTF8.GetString(magic) == "XINYUAN";
    }
}

file static class Rc4
{
    private static readonly byte[] Key = Convert.FromHexString("e4211314d047b50a");

    public static void Decrypt(ref Span<byte> data)
    {
        var key = Key.AsSpan();

        var kt = (stackalloc byte[256]);
        for (int i = 0; i < kt.Length; i++)
            kt[i] = (byte)i;

        var swap = 0;
        for (int i = 0; i < kt.Length; i++)
        {
            var a = kt[i];
            swap = (swap + a + key[i % key.Length]) & 0xff;
            kt[i] = kt[swap];
            kt[swap] = a;
        }

        byte j = 0, k = 0;
        for (int i = 0; i < data.Length; i++)
        {
            j++;
            var a = kt[j];
            k = (byte)(a + k);
            kt[j] = kt[k];
            kt[k] = a;

            data[i] ^= kt[(byte)(a + kt[j])];
        }
    }
}