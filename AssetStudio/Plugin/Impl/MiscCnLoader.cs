using System;
using System.Buffers.Binary;
using System.Drawing;
using System.IO;
using AssetStudio.Plugin.Streams;

namespace AssetStudio.Plugin.Impl;

public class MiscCnLoader : FileLoader
{
    public override int Priority => 11;
    public override bool ReturnsBundleFile => true;

    public override BundleFile ProcessBundle(FileReader reader)
    {
        var bundle = new BundleFile();
        
        bundle.Initialize(reader);
        bundle.ReadHeader(reader);

        bundle.m_Header.size -= 0x10CE1029;
        bundle.m_Header.size ^= 0x37F00D0F;
        bundle.m_Header.compressedBlocksInfoSize -= 0x8670814;
        bundle.m_Header.uncompressedBlocksInfoSize -= 0xDFC0343;
        bundle.m_Header.uncompressedBlocksInfoSize ^= 0x166C2D5C;
        bundle.m_Header.uncompressedBlocksInfoSize ^= bundle.m_Header.compressedBlocksInfoSize;
        bundle.m_Header.compressedBlocksInfoSize ^= 0x37F00D0F;

        bundle.ReadBlocksInfoAndDirectory(reader);

        foreach (var block in bundle.m_BlocksInfo)
        {
            if (((uint) block.flags & 0x80) != 0)
            {
                block.compressedSize ^= block.uncompressedSize;
                block.compressedSize ^= 0x166C2D5C;
                block.uncompressedSize ^= 0x37F00D0F;
            }
        }

        foreach (var directoryInfo in bundle.m_DirectoryInfo)
        {
            if ((directoryInfo.flags & 8) != 0)
            {
                directoryInfo.offset ^= directoryInfo.size;
                directoryInfo.offset ^= 0x3A6426D4;
                directoryInfo.size ^= 0x1BF80687;
            }
        }

        using (var blocksStream = bundle.CreateBlocksStream(reader.FullPath))
        {
            bundle.ReadBlocks(reader, blocksStream);
            bundle.ReadFiles(blocksStream, reader.FullPath);
        }

        return bundle;
    }

    public override Stream ProcessFile(Stream file, string filename) => new FakeHeaderLoader().ProcessFile(file, filename);

    public override bool CanProcessFile(Stream file, string filename)
    {
        var reader = new EndianBinaryReader(file);
        var bundleFile = new BundleFile();
        bundleFile.Initialize(reader);
        if (!bundleFile.m_Header.signature.EndsWith("UnityFS"))
            return false;

        bundleFile.ReadHeader(reader);
        return ((uint) bundleFile.m_Header.flags & 0x400) != 0;
    }
}