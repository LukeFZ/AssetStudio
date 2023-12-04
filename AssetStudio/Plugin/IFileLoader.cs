using System.IO;

namespace AssetStudio.Plugin
{
    public interface IFileLoader
    {
        public int Priority { get; }
        public Stream ProcessFile(Stream file, string filename);
        public bool CanProcessFile(Stream file, string filename);
    }

    public abstract class FileLoader : IFileLoader
    {
        public virtual int Priority => 100;
        public abstract Stream ProcessFile(Stream file, string filename);
        public abstract bool CanProcessFile(Stream file, string filename);
    }
}