using H4xbr1x;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace H4xbr1xDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            /*const string kernel32dump = "..\\..\\..\\..\\basicwindow32_kernel32.bin";
            if (!File.Exists(kernel32dump))
            {
                Console.WriteLine("Can't load file {0:s}", kernel32dump);
                return;
            }
            var kernel32mem = File.ReadAllBytes(kernel32dump);
            var peFile = PeParser.ParseFromMem(kernel32mem);*/
            Process dummy = ProcessQuery.OpenProcessByName("BasicWindow32.exe");
            Console.WriteLine("Process {0:s}", dummy.processEntry.szExeFile);
            var dllname = "kernel32.dll";
            var modules = ProcessQuery.GetModuleList(dummy);
            ProcessQuery.MODULEENTRY32 me = ProcessQuery.GetModuleByName(dummy, dllname);
            Console.WriteLine("kernel32 dll name: {0:s}", me.szModule);
            var peFile = PeParser.ParseFromProcess(dummy, (uint)me.modBaseAddr);
            Console.WriteLine("Dos signature: {0:x}", peFile.dosHeader.e_magic);
            Console.WriteLine("Function names stored at {0:x}", peFile.exportDirectory.AddressOfNames);
            Console.WriteLine("Function addresses stored at {0:x}", peFile.exportDirectory.AddressOfFunctions);
            Console.WriteLine("Function ordinals stored at {0:x}", peFile.exportDirectory.AddressOfNameOrdinals);
            Console.WriteLine("Ordinal base: {0:d}", peFile.exportDirectory.Base);
            Console.WriteLine("LoadLibraryA offset: {0:x}", peFile.exports["LoadLibraryA"]);
            Console.WriteLine("GetModuleHandleA offset: {0:x}", peFile.exports["GetModuleHandleA"]);
            Console.WriteLine("GetModuleHandleW offset: {0:x}", peFile.exports["GetModuleHandleW"]);

            // let's try injecting a dll
            const string dll = "C:\\Users\\User\\source\\repos\\H4xbr1x\\H4xbr1xDemo\\hl1dll.dll";

            if (!File.Exists(dll))
            {
                Console.WriteLine("Can't load file {0:s}", dll);
                return;
            }

            var codeOffset = (uint)ProcessQuery.VirtualAllocEx(
                dummy.hProcess,
                (IntPtr)0,
                1024,
                ProcessQuery.AllocationType.Commit | ProcessQuery.AllocationType.Reserve,
                ProcessQuery.MemoryProtection.ExecuteReadWrite);
            var stringOffset = codeOffset + 16;
            var shellcode = new byte[]
            {
                0xB8, 0x48, 0x48, 0x48, 0x48, // mov eax, 0x48484848
                0x50, // push eax
                0xE8, 0x39, 0x39, 0x39, 0x39, // call 0x39393939
                0xC3 // ret
            };

            BitConverter.TryWriteBytes(new Span<byte>(shellcode, 1, 4), stringOffset);
            BitConverter.TryWriteBytes(new Span<byte>(shellcode, 7, 4), (uint)(peFile.exports["LoadLibraryA"] - 11 - codeOffset));
            Console.WriteLine("Shellcode string address: {0:x}", BitConverter.ToUInt32(shellcode, 1));
            Console.WriteLine("Shellcode LoadLibrary address: {0:x}", BitConverter.ToUInt32(shellcode, 7));
            ProcessQuery.WriteProcessMemory(dummy.hProcess, (IntPtr)stringOffset, dll, dll.Length+1, out _);
            ProcessQuery.WriteProcessMemory(dummy.hProcess, (IntPtr)codeOffset, shellcode, shellcode.Length, out _);
            ProcessQuery.CreateRemoteThread(dummy.hProcess, (IntPtr)0, 0, (IntPtr)codeOffset, (IntPtr)0, 0, out _);

            Console.ReadLine();
            Console.WriteLine("Freeing memory at {0:x}", codeOffset);
            ProcessQuery.VirtualFreeEx(dummy.hProcess, (IntPtr)codeOffset, 0, ProcessQuery.AllocationType.Release);
        }
    }
}
