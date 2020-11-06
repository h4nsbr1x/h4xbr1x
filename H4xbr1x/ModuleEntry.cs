using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace H4xbr1x
{
    public class ModuleEntry
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public int modBaseSize;
        public IntPtr hModule;
        public string szModule;
        public string szExePath;

        public ModuleEntry(ProcessQuery.MODULEENTRY32 me)
        {
            this.dwSize = me.dwSize;
            this.th32ModuleID = me.th32ModuleID;
            this.th32ProcessID = me.th32ProcessID;
            this.GlblcntUsage = me.GlblcntUsage;
            this.ProccntUsage = me.ProccntUsage;
            this.modBaseAddr = me.modBaseAddr;
    }
    }
}
