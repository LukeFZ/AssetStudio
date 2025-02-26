using System.IO;
using System.Text;

namespace AssetStudio.Plugin.Impl;

public partial class SeasunLoader : FileLoader
{
    private const string Magic = "SeasunC";

    public override Stream ProcessFile(Stream file, string filename)
    {
        var dataLength = file.Length - file.Position - Magic.Length - 1;
        var data = BigArrayPool<byte>.Shared.Rent((int)dataLength);

        file.Position += Magic.Length + 1;
        file.ReadExactly(data, 0, (int)dataLength);

        var initialOffset = CalculateInitialValue(filename) + 8;
        for (int i = 0; i < dataLength; i++)
            data[i] ^= XorKey[(initialOffset + i) % XorKey.Length];

        var ms = new MemoryStream();
        ms.Write("UnityFS\0"u8);
        ms.Write(data, 0, (int)dataLength);
        ms.Position = 0;

        BigArrayPool<byte>.Shared.Return(data);

        return ms;
    }

    public override bool CanProcessFile(Stream file, string filename)
    {
        var reader = new EndianBinaryReader(file);
        return reader.ReadStringToNull() == Magic;
    }

    private static int CalculateInitialValue(string filename)
    {
        var value = 0;
        foreach (var letter in Encoding.UTF8.GetBytes(Path.GetFileName(filename)))
        {
            value *= 0x83;
            value += 0x80 > letter ? letter | 0x20 : letter;
        }

        return value & 0xffff;
    }
}