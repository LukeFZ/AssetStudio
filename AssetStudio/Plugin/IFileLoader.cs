using System;
using System.IO;

namespace AssetStudio.Plugin
{
    public interface IFileLoader
    {
        public int Priority { get; }
        public bool ReturnsBundleFile { get; }
        public Stream ProcessFile(Stream file, string filename);
        public BundleFile ProcessBundle(FileReader reader);
        public bool CanProcessFile(Stream file, string filename);
    }

    public abstract class FileLoader : IFileLoader
    {
        public virtual int Priority => 100;
        public virtual bool ReturnsBundleFile => false;

        public virtual Stream ProcessFile(Stream file, string filename) => file;
        public virtual BundleFile ProcessBundle(FileReader reader) => throw new NotImplementedException();
        public abstract bool CanProcessFile(Stream file, string filename);
    }
}