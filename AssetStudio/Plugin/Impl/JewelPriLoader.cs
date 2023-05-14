using System.IO;

namespace AssetStudio.Plugin.Impl;

public class JewelPriLoader : IFileLoader
{
    public Stream ProcessFile(Stream file, string filename)
    {
        using var reader = new EndianBinaryReader(file);
        var fakeHeader = reader.ReadStringToNull(8);
        var fileData = reader.ReadBytes((int)file.Length - fakeHeader.Length - 1);
        var offset = 0;

        for (; offset < 0x250; offset++)
        {
            if (fileData[offset] == 'U'
                && fileData[offset + 1] == 'n'
                && fileData[offset + 2] == 'i'
                && fileData[offset + 3] == 't'
                && fileData[offset + 4] == 'y'
                && fileData[offset + 5] == 'F'
                && fileData[offset + 6] == 'S')
                break;
        }

        var memStream = new MemoryStream();
        memStream.Write(fileData, offset, fileData.Length - offset);
        memStream.Seek(0, SeekOrigin.Begin);
        return memStream;
    }

    public bool CanProcessFile(Stream file, string filename)
    {
        if (file.Length < 8) return false;

        var reader = new EndianBinaryReader(file);
        var fakeHeader = reader.ReadStringToNull(8);
        if (fakeHeader != "UnityFS") return false;
        var fileData = reader.ReadBytes((int) file.Length - fakeHeader.Length - 1);

        for (int i = 0; i < 0x250; i++)
        {
            if (fileData[i] == 'U'
                && fileData[i + 1] == 'n'
                && fileData[i + 2] == 'i'
                && fileData[i + 3] == 't'
                && fileData[i + 4] == 'y'
                && fileData[i + 5] == 'F'
                && fileData[i + 6] == 'S')
                return true;
        }

        return false;
    }
}