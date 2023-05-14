using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace AssetStudio.Plugin
{
    public static class PluginManager
    {
        public static readonly List<IFileLoader> RegisteredFileLoaders = new();

        private static bool _isLoaded;

        public static List<string> LoadPlugins()
        {
            var failedPlugins = new List<string>();

            foreach (var type in Assembly
                         .GetCallingAssembly()
                         .GetTypes()
                         .Where(type => type
                             .GetInterfaces()
                             .Contains(typeof(IFileLoader)))) {
                try
                {
                    RegisteredFileLoaders.Add(type.GetConstructor(Type.EmptyTypes)?.Invoke(null) as IFileLoader);
                }
                catch (Exception e)
                {
                    failedPlugins.Add(type.Name);
                }
            }

            _isLoaded = true;

            return failedPlugins;
        }

        public static Stream ParseFileUsingPlugin(Stream fileStream, string path)
        {
            if (fileStream.Position >= fileStream.Length)
                return null;

            if (!_isLoaded)
                LoadPlugins();

            foreach (var loader in RegisteredFileLoaders)
            {
                if (loader.CanProcessFile(fileStream, path))
                {
                    fileStream.Seek(0, SeekOrigin.Begin);
                    return loader.ProcessFile(fileStream, path);
                }
                fileStream.Seek(0, SeekOrigin.Begin);
            }

            return null;
        }
    }
}