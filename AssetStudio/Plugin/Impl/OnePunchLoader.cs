using System.IO;

namespace AssetStudio.Plugin.Impl;

public class OnePunchLoader : FileLoader
{
    public override bool ReturnsBundleFile => true;

    public override bool CanProcessFile(Stream file, string filename)
    {
        var reader = new EndianBinaryReader(file);
        var bundleFile = new BundleFile();
        bundleFile.Initialize(reader);
        if (bundleFile.m_Header.signature != "UnityFS")
            return false;

        if (reader.ReadUInt32() == 0 && reader.ReadUInt32() == 0)
            return false;

        for (int i = 0; i < 4; i++)
        {
            if (reader.ReadUInt32() == 0)
                return false;
        }

        return true;
    }

    public override BundleFile ProcessBundle(FileReader reader)
    {
        var bundle = new BundleFile();
        bundle.m_Header.signature = reader.ReadStringToNull();
        bundle.m_Header.version = 7;
        bundle.m_Header.unityVersion = "2019.4.40f1";
        bundle.m_Header.unityRevision = "5.x.x";

        var encodedCompressed = reader.ReadUInt32();
        ulong encodedSize = reader.ReadUInt32();

        reader.ReadUInt32(); // unused?
        var encodedFlags = reader.ReadUInt32();
        ulong encodedSize2 = reader.ReadUInt32();
        var encodedUncompressed = reader.ReadUInt32();

        bundle.m_Header.compressedBlocksInfoSize = Decode(encodedCompressed) ^ encodedFlags;
        bundle.m_Header.uncompressedBlocksInfoSize = Decode(encodedUncompressed) ^ encodedCompressed;
        bundle.m_Header.flags = (ArchiveFlags)(Decode(encodedFlags) ^ 0x70020017);

        bundle.m_Header.size = (long)(
            ((encodedSize2 & 0x000000FF)) |
            ((encodedSize2 & 0xFFFFFF00) << 32) |
            (encodedSize  << 08)
        );
        bundle.m_Header.size ^= (long)((ulong)encodedFlags << 32) | encodedCompressed;

        bundle.ReadBlocksInfoAndDirectory(reader, (compressed) =>
        {
            byte[] key = {0x1E, 0x1E, 0x1, 0x1, 0xFC};

            for (int i = 0; i < compressed.Length; i++)
                compressed[i] ^= key[i % key.Length];
        });
        using var blocksStream = bundle.CreateBlocksStream(reader.FullPath);
        bundle.ReadBlocks(reader, blocksStream);
        bundle.ReadFiles(blocksStream, reader.FullPath);

        return bundle;

        static uint Decode(uint value)
            => ((value >> 05) & 0x00FFE000) |
               ((value >> 29) & 0x00000007) |
               ((value << 14) & 0xFF000000) |
               ((value << 03) & 0x00001FF8);
    }
}