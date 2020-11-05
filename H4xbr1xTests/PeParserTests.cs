using H4xbr1x;
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Xunit;

namespace H4xbr1xTests
{
    public class PeParserTests
    {
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

        [Fact]
        public void TestCanGetMZHeader32()
        {
            const string kernel32dump = "..\\..\\..\\..\\basicwindow32_kernel32.bin";
            Assert.True(File.Exists(kernel32dump));
            var kernel32mem = File.ReadAllBytes(kernel32dump);
            var dosHeader = Deserialize<PeParser.IMAGE_DOS_HEADER>(kernel32mem, 0);
            Assert.Equal<ushort>(0x5A4D, dosHeader.e_magic);
            var peHeaderOffset = dosHeader.e_lfanew;
            var peHeader = Deserialize<PeParser.IMAGE_FILE_HEADER>(kernel32mem, peHeaderOffset);
            Assert.Equal<uint>(0x00004550, peHeader.Signature);
            var optionalHeaderOffset = peHeaderOffset + Marshal.SizeOf(typeof(PeParser.IMAGE_FILE_HEADER));
            var optionalHeader = Deserialize<PeParser.IMAGE_OPTIONAL_HEADER32>(kernel32mem, optionalHeaderOffset);
            // 0x020B for 64 bit, 0x010B for 32 bit
            Assert.Equal<ushort>(0x010B, optionalHeader.Magic);
            var exportDirectoryRefOffset = PeParser.GetExportDirectoryRefOffset32(dosHeader);
            var exportDirectoryRef = Deserialize<PeParser.IMAGE_DATA_DIRECTORY>(kernel32mem, (int)exportDirectoryRefOffset);
            Assert.Equal<uint>(0x170, exportDirectoryRefOffset);
            Assert.Equal<uint>(0x10, optionalHeader.NumberOfRvaAndSizes);
            Assert.Equal<uint>(0x972C0, exportDirectoryRef.VirtualAddress);
        }
    }
}
