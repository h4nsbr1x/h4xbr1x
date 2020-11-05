using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace H4xbr1x
{
    public static class PeParser
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct IMAGE_DOS_HEADER
        {  // DOS .EXE header
            public ushort e_magic;         // Magic number
            public ushort e_cblp;          // Bytes on last page of file
            public ushort e_cp;            // Pages in file
            public ushort e_crlc;          // Relocations
            public ushort e_cparhdr;       // Size of header in paragraphs
            public ushort e_minalloc;      // Minimum extra paragraphs needed
            public ushort e_maxalloc;      // Maximum extra paragraphs needed
            public ushort e_ss;            // Initial (relative) SS value
            public ushort e_sp;            // Initial SP value
            public ushort e_csum;          // Checksum
            public ushort e_ip;            // Initial IP value
            public ushort e_cs;            // Initial (relative) CS value
            public ushort e_lfarlc;        // File address of relocation table
            public ushort e_ovno;          // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res;        // Reserved public ushorts
            public ushort e_oemid;         // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo;       // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;      // Reserved public ushorts
            public int e_lfanew;          // File address of new exe header (0x3C)
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct IMAGE_FILE_HEADER
        {
            // not in the standard but super weird leaving it out
            public uint Signature;
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Reserved1;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            //IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            //IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string Name;
            public uint PhysicalAddressVirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct IMAGE_EXPORT_DIRECTORY {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;     // RVA from base of image
            public uint AddressOfNames;         // RVA from base of image
            public uint AddressOfNameOrdinals;  // RVA from base of image
        }
        public static string ReadCString(byte[] input, int offset)
        {
            var length = Array.FindIndex(input, offset, (x) => x == 0) - offset;
            return Encoding.GetEncoding(0).GetString(input, offset, length);
        }
        public static string ReadCString(Process process, uint baseAddress)
        {
            IEnumerable<Byte> bytes = new List<Byte>();
            uint offset = 0;
            int length = -1;
            do
            {
                var tempBytes = new byte[256];
                ProcessQuery.ReadProcessMemory(process.hProcess, (IntPtr)(baseAddress + offset), tempBytes, (IntPtr)256, out _);
                bytes = bytes.Concat(tempBytes);
                offset += 256;
                length = Array.FindIndex(bytes.ToArray(), 0, (x) => x == 0);
            }
            while (length == -1);
            return Encoding.GetEncoding(0).GetString(bytes.ToArray(), 0, length);
        }
        public static T Deserialize<T>(byte[] input, int offset)
            where T : struct
        {
            var size = Marshal.SizeOf(typeof(T));
            var ptr = Marshal.AllocHGlobal(size);
            Marshal.Copy(input, offset, ptr, size);
            var output = (T)Marshal.PtrToStructure(ptr, typeof(T));
            Marshal.FreeHGlobal(ptr);
            return output;
        }
        public static T Deserialize<T>(Process process, uint baseAddress)
            where T : struct
        {
            var output = (object) new T();
            ProcessQuery.ReadProcessMemory(process.hProcess, (IntPtr)baseAddress, output, (IntPtr)Marshal.SizeOf(typeof(T)), out _);
            return (T) output;
        }
        public static IMAGE_DOS_HEADER GetDosHeader(byte[] dll)
        {
            return PeParser.Deserialize<IMAGE_DOS_HEADER>(dll, 0);
        }
        public static IMAGE_DOS_HEADER GetDosHeader(Process process, uint baseAddress)
        {
            return Deserialize<IMAGE_DOS_HEADER>(process, baseAddress);
        }

        public static IMAGE_FILE_HEADER GetPeHeader(byte[] dll, IMAGE_DOS_HEADER dosHeader)
        {
            return PeParser.Deserialize<PeParser.IMAGE_FILE_HEADER>(dll, dosHeader.e_lfanew);
        }

        public static IMAGE_FILE_HEADER GetPeHeader(Process process, uint baseAddress, IMAGE_DOS_HEADER dosHeader)
        {
            return PeParser.Deserialize<PeParser.IMAGE_FILE_HEADER>(process, baseAddress + (uint)dosHeader.e_lfanew);
        }

        public static IMAGE_OPTIONAL_HEADER32 GetOptionalHeader32(byte[] dll, IMAGE_DOS_HEADER dosHeader)
        {
            var optionalHeaderOffset = dosHeader.e_lfanew + Marshal.SizeOf(typeof(PeParser.IMAGE_FILE_HEADER));
            return PeParser.Deserialize<PeParser.IMAGE_OPTIONAL_HEADER32>(dll, optionalHeaderOffset);
        }

        public static IMAGE_OPTIONAL_HEADER32 GetOptionalHeader32(Process process, uint baseAddress, IMAGE_DOS_HEADER dosHeader)
        {
            var optionalHeaderOffset = dosHeader.e_lfanew + Marshal.SizeOf(typeof(PeParser.IMAGE_FILE_HEADER));
            return PeParser.Deserialize<PeParser.IMAGE_OPTIONAL_HEADER32>(process, baseAddress + (uint)optionalHeaderOffset);
        }

        public static IMAGE_EXPORT_DIRECTORY GetExportDirectory32(byte[] dll, IMAGE_DOS_HEADER dosHeader)
        {
            var exportDirectoryRefOffset = PeParser.GetExportDirectoryRefOffset32(dosHeader);
            var exportDirectoryRef = PeParser.Deserialize<PeParser.IMAGE_DATA_DIRECTORY>(dll, (int)exportDirectoryRefOffset);
            return PeParser.Deserialize<PeParser.IMAGE_EXPORT_DIRECTORY>(dll, (int)exportDirectoryRef.VirtualAddress);
        }

        public static IMAGE_EXPORT_DIRECTORY GetExportDirectory32(Process process, uint baseAddress, IMAGE_DOS_HEADER dosHeader)
        {
            var exportDirectoryRefOffset = PeParser.GetExportDirectoryRefOffset32(dosHeader);
            var exportDirectoryRef = PeParser.Deserialize<PeParser.IMAGE_DATA_DIRECTORY>(process, baseAddress + (uint)exportDirectoryRefOffset);
            return PeParser.Deserialize<PeParser.IMAGE_EXPORT_DIRECTORY>(process, baseAddress + (uint)exportDirectoryRef.VirtualAddress);
        }

        public static Dictionary<string, uint> BuildExports(byte[] dll, IMAGE_EXPORT_DIRECTORY exportDirectory)
        {
            var exports = new Dictionary<string, uint>();

            for (var i = 0; i < exportDirectory.NumberOfNames; i++)
            {
                var functionNameAddress = BitConverter.ToUInt32(dll, (int)exportDirectory.AddressOfNames + (4 * i));
                var functionName = PeParser.ReadCString(dll, (int)functionNameAddress);
                var functionOrdinal = BitConverter.ToUInt16(dll, (int)exportDirectory.AddressOfNameOrdinals + (2 * i));
                var offset = (int)(functionOrdinal);
                var functionAddress = BitConverter.ToUInt32(dll, (int)exportDirectory.AddressOfFunctions + (4 * offset));
                exports[functionName] = functionAddress;
            }

            return exports;
        }

        public static Dictionary<string, uint> BuildExports(Process process, uint baseAddress, IMAGE_EXPORT_DIRECTORY exportDirectory)
        {
            var exports = new Dictionary<string, uint>();

            for (var i = 0; i < exportDirectory.NumberOfNames; i++)
            {
                var functionNameAddress = ProcessQuery.ReadRemote<uint>(process, (IntPtr)(baseAddress + exportDirectory.AddressOfNames + (4 * i)));
                var functionName = PeParser.ReadCString(process, (uint)(baseAddress + functionNameAddress));
                var functionOrdinal = ProcessQuery.ReadRemote<ushort>(process, (IntPtr)(baseAddress + exportDirectory.AddressOfNameOrdinals + (2 * i)));
                var offset = (int)(functionOrdinal);
                var functionAddress = ProcessQuery.ReadRemote<uint>(process, (IntPtr)(baseAddress + exportDirectory.AddressOfFunctions + (4 * offset)));
                exports[functionName] = baseAddress+functionAddress;
            }

            return exports;
        }

        public static PeFile32 ParseFromMem(byte[] dll)
        {
            var dosHeader = GetDosHeader(dll);
            var peHeader = GetPeHeader(dll, dosHeader);
            var optionalHeader = GetOptionalHeader32(dll, dosHeader);
            var exportDirectory = GetExportDirectory32(dll, dosHeader);
            var exports = BuildExports(dll, exportDirectory);

            return new PeFile32(dosHeader, peHeader, optionalHeader, exportDirectory, exports);
        }

        public static PeFile32 ParseFromProcess(Process process, uint baseAddress)
        {
            var dosHeader = GetDosHeader(process, baseAddress);
            var peHeader = GetPeHeader(process, baseAddress, dosHeader);
            var optionalHeader = GetOptionalHeader32(process, baseAddress, dosHeader);
            var exportDirectory = GetExportDirectory32(process, baseAddress, dosHeader);
            var exports = BuildExports(process, baseAddress, exportDirectory);

            return new PeFile32(dosHeader, peHeader, optionalHeader, exportDirectory, exports);
        }

        public static uint GetExportDirectoryRefOffset32(in IMAGE_DOS_HEADER dosHeader)
        {
            return (uint)dosHeader.e_lfanew +
                (uint)Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) +
                (uint)Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER32));
        }

        public static uint GetExportDirectoryRefOffset32(byte[] dll)
        {
            return GetExportDirectoryRefOffset32(GetDosHeader(dll));
        }
    }
}

