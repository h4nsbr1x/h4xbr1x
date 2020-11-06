using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static H4xbr1x.PeParser;

namespace H4xbr1x
{
    public class PeFile64 : IPeFile
    {
        private IMAGE_DOS_HEADER dosHeader;
        private IMAGE_FILE_HEADER peHeader;
        private IMAGE_OPTIONAL_HEADER64 optionalHeader;
        private IMAGE_EXPORT_DIRECTORY exportDirectory;
        private Dictionary<string, IntPtr> exports;

        public PeFile64(IMAGE_DOS_HEADER dosHeader, IMAGE_FILE_HEADER peHeader, IMAGE_OPTIONAL_HEADER64 optionalHeader, IMAGE_EXPORT_DIRECTORY exportDirectory, Dictionary<string, IntPtr> exports)
        {
            this.DosHeader = dosHeader;
            this.PeHeader = peHeader;
            this.OptionalHeader = optionalHeader;
            this.ExportDirectory = exportDirectory;
            Exports = exports;
        }

        public Dictionary<string, IntPtr> Exports { get => exports; set => exports = value; }
        public IMAGE_DOS_HEADER DosHeader { get => dosHeader; set => dosHeader = value; }
        public IMAGE_FILE_HEADER PeHeader { get => peHeader; set => peHeader = value; }
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader { get => optionalHeader; set => optionalHeader = value; }
        public IMAGE_EXPORT_DIRECTORY ExportDirectory { get => exportDirectory; set => exportDirectory = value; }
    }
}
