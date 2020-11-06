using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static H4xbr1x.PeParser;

namespace H4xbr1x
{
    public interface IPeFile
    {
        Dictionary<string, IntPtr> Exports { get; set; }
        IMAGE_DOS_HEADER DosHeader { get; set; }
        IMAGE_FILE_HEADER PeHeader { get; set; }
        IMAGE_EXPORT_DIRECTORY ExportDirectory { get; set; }
    }
}
