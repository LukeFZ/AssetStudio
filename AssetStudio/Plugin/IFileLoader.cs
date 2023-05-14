using System.IO;

namespace AssetStudio.Plugin
{
    public interface IFileLoader
    {
        public Stream ProcessFile(Stream file, string filename);
        public bool CanProcessFile(Stream file, string filename);
    }
}