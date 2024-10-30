﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AssetStudio
{
    public class AssetInfo
    {
        public int preloadIndex;
        public int preloadSize;
        public PPtr<Object> asset;

        public AssetInfo(ObjectReader reader)
        {
            if (reader.m_Version < SerializeFileFormatVersion.Unknown_14)
            if (reader.m_Version < SerializedFileFormatVersion.Unknown_14)
            {
                reader.ReadInt32();
            }
            else
            {
                reader.ReadInt64();
            }

            preloadIndex = reader.ReadInt32();
            preloadSize = reader.ReadInt32();
            asset = new PPtr<Object>(reader);
        }
    }

    public sealed class AssetBundle : NamedObject
    {
        public PPtr<Object>[] m_PreloadTable;
        public KeyValuePair<string, AssetInfo>[] m_Container;

        public AssetBundle(ObjectReader reader) : base(reader)
        {
            var m_PreloadTableSize = reader.ReadInt32();
            m_PreloadTable = new PPtr<Object>[m_PreloadTableSize];
            for (int i = 0; i < m_PreloadTableSize; i++)
            {
                m_PreloadTable[i] = new PPtr<Object>(reader);
            }

            var m_ContainerSize = reader.ReadInt32();
            m_Container = new KeyValuePair<string, AssetInfo>[m_ContainerSize];
            for (int i = 0; i < m_ContainerSize; i++)
            {
                var assetInfo = new AssetInfo(reader);
                var container = reader.ReadAlignedString();
                m_Container[i] = new KeyValuePair<string, AssetInfo>(container, assetInfo);
            }
        }
    }
}
