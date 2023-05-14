using System.IO;

namespace AssetStudio.Plugin.Impl;

public class TenkafuMALoader : IFileLoader
{
    public Stream ProcessFile(Stream file, string filename)
    {
        var obfByte = file.ReadByte();

        var memStream = new MemoryStream();
        file.CopyTo(memStream);
        memStream.Seek(0, SeekOrigin.Begin);
        return memStream;
    }

    public bool CanProcessFile(Stream file, string filename)
    {
        var reader = new EndianBinaryReader(file);
        var obfByte = reader.ReadByte();
        var actualHeader = reader.ReadStringToNull(20);
        return actualHeader == "UnityFS";
    }
}