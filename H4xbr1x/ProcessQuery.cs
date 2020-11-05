using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;

namespace H4xbr1x
{
    public static class ProcessQuery
    {
        public static readonly IntPtr INVALID_HANDLE_VALUE = (IntPtr)(-1);
        [Flags]
        public enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001FFFFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            SetSessionId = 0x00000004,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x00000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            SuspendResume = 0x00000800,
            QueryLimitedInformation = 0x00001000,
            SetLimitedInformation = 0x00002000,
            Delete = 0x00010000,
            ReadControl = 0x00020000,
            WriteDac = 0x00040000,
            WriteOwner = 0x00080000,
            Synchronize = 0x00100000
        }
        [Flags]
        public enum MbiStateFlags : uint
        {
            Commit = 0x00001000,
            Reserve = 0x00002000,
            Free = 0x00010000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct PROCESSENTRY32
        {
            const int MAX_PATH = 260;
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct MODULEENTRY32
        {
            const int MAX_MODULE_NAME32 = 255;
            const int MAX_PATH = 260;
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public IntPtr modBaseAddr;
            public int modBaseSize;
            public IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_MODULE_NAME32 + 1)]
            public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            public string szExePath;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct MEMORY_BASIC_INFORMATION32
        {
            public uint BaseAddress;
            public uint AllocationBase;
            public uint AllocationProtect;
            public uint RegionSize;
            public MbiStateFlags State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct MEMORY_BASIC_INFORMATION64
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public uint AllocationProtect;
            public uint _alignment1;
            public ulong RegionSize;
            public MbiStateFlags State;
            public uint Protect;
            public uint Type;
            public uint _alignment2;
        }

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public static extern IntPtr CreateToolhelp32Snapshot([In] uint dwFlags, [In] uint th32ProcessID);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public static extern bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public static extern bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        public static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll")]
        public static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public static extern uint VirtualQueryEx(IntPtr hProcess, IntPtr basePtr, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, IntPtr dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] float[] lpBuffer, IntPtr dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out, MarshalAs(UnmanagedType.AsAny)] object lpBuffer, IntPtr dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
          IntPtr hProcess,
          IntPtr lpBaseAddress,
          byte[] lpBuffer,
          int dwSize,
          out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
          IntPtr hProcess,
          IntPtr lpBaseAddress,
          [MarshalAs(UnmanagedType.AsAny)] object lpBuffer,
          int dwSize,
          out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess,
            IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
            IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        static public T ReadRemote<T>(Process process, IntPtr lpBaseAddress)
        {
            var buffer = new T[1];
            ReadProcessMemory(process.hProcess, lpBaseAddress, buffer, (IntPtr)Marshal.SizeOf(typeof(T)), out _);

            return buffer[0];
        }

        static public IEnumerable<PROCESSENTRY32> GetProcessList()
        {
            var hSnapshot = CreateToolhelp32Snapshot((uint)SnapshotFlags.Process, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE)
                return default;

            var processEntry = new PROCESSENTRY32();
            processEntry.dwSize = (uint)Marshal.SizeOf(processEntry);

            var processes = new List<PROCESSENTRY32>();

            if (Process32First(hSnapshot, ref processEntry))
            {
                do
                {
                    processes.Add(processEntry);
                }
                while (Process32Next(hSnapshot, ref processEntry));
            }

            CloseHandle(hSnapshot);

            return processes;
        }

        static public Process OpenProcessByStruct(PROCESSENTRY32 processEntry)
        {
            return new Process(processEntry);
        }

        public static Process OpenProcessByName(string name)
        {
            PROCESSENTRY32 processEntry = GetProcessList().Where(pe => pe.szExeFile == name).FirstOrDefault();
            if (processEntry.Equals(default))
                return default;

            return OpenProcessByStruct(processEntry);
        }

        static public IEnumerable<MODULEENTRY32> GetModuleList(Process process)
        {
            var hSnapshot = CreateToolhelp32Snapshot((uint)SnapshotFlags.Module | (uint)SnapshotFlags.Module32, process.processEntry.th32ProcessID);

            if (hSnapshot == INVALID_HANDLE_VALUE)
                return default;

            var moduleEntry = new MODULEENTRY32();
            moduleEntry.dwSize = (uint)Marshal.SizeOf(moduleEntry);

            var modules = new List<MODULEENTRY32>();

            if (Module32First(hSnapshot, ref moduleEntry))
            {
                do
                {
                    modules.Add(moduleEntry);
                }
                while (Module32Next(hSnapshot, ref moduleEntry));
            }

            CloseHandle(hSnapshot);

            return modules;
        }

        public static MODULEENTRY32 GetModuleByName(Process process, string moduleName)
        {
            return GetModuleList(process).Where(me => me.szModule.Equals(moduleName, StringComparison.CurrentCultureIgnoreCase)).FirstOrDefault();
        }

        public static IntPtr InjectDll(Process process, string moduleName)
        {
            IntPtr remoteModuleName = VirtualAllocEx(process.hProcess, default, (uint)Marshal.SizeOf(moduleName) + 1, AllocationType.Reserve | AllocationType.Commit, MemoryProtection.ReadWrite);
            IntPtr bytesWritten;
            WriteProcessMemory(process.hProcess, remoteModuleName, moduleName, Marshal.SizeOf(moduleName), out bytesWritten);
            return default;
        }
    }
}
