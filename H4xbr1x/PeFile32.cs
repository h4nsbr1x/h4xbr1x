using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static H4xbr1x.PeParser;

namespace H4xbr1x
{
    public class PeFile32
    {
        public IMAGE_DOS_HEADER dosHeader;
        public IMAGE_FILE_HEADER peHeader;
        public IMAGE_OPTIONAL_HEADER32 optionalHeader;
        public IMAGE_EXPORT_DIRECTORY exportDirectory;
        public Dictionary<string, uint> exports;

        public PeFile32(IMAGE_DOS_HEADER dosHeader, IMAGE_FILE_HEADER peHeader, IMAGE_OPTIONAL_HEADER32 optionalHeader, IMAGE_EXPORT_DIRECTORY exportDirectory, Dictionary<string, uint> exports)
        {
            this.dosHeader = dosHeader;
            this.peHeader = peHeader;
            this.optionalHeader = optionalHeader;
            this.exportDirectory = exportDirectory;
            this.exports = exports;
        }
    }
}
