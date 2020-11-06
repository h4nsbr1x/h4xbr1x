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
            Process dummy = ProcessQuery.OpenProcessByName("BasicWindow64.exe");
            Console.WriteLine("Process {0:s}", dummy.processEntry.szExeFile);
            var dllname = "kernel32.dll";
            var modules = ProcessQuery.GetModuleList(dummy);
            ProcessQuery.MODULEENTRY32 me = ProcessQuery.GetModuleByName(dummy, dllname);
            Console.WriteLine("kernel32 dll name: {0:s}", me.szModule);
            var peFile = PeParser.ParseFromProcess(dummy, me.modBaseAddr);
            Console.WriteLine("Base address of kernel32.dll: {0:x}", (ulong)me.modBaseAddr);
            Console.WriteLine("Dos signature: {0:x}", peFile.DosHeader.e_magic);
            Console.WriteLine("Function names stored at {0:x}", peFile.ExportDirectory.AddressOfNames);
            Console.WriteLine("Function addresses stored at {0:x}", peFile.ExportDirectory.AddressOfFunctions);
            Console.WriteLine("Function ordinals stored at {0:x}", peFile.ExportDirectory.AddressOfNameOrdinals);
            Console.WriteLine("Ordinal base: {0:d}", peFile.ExportDirectory.Base);
            Console.WriteLine("LoadLibraryA offset: {0:x}", (ulong)peFile.Exports["LoadLibraryA"]);
            Console.WriteLine("GetModuleHandleA offset: {0:x}", (ulong)peFile.Exports["GetModuleHandleA"]);
            Console.WriteLine("GetModuleHandleW offset: {0:x}", (ulong)peFile.Exports["GetModuleHandleW"]);

            //return;

            // let's try injecting a dll
            const string dll = "C:\\Users\\User\\source\\repos\\H4xbr1x\\H4xbr1xDemo\\hl1dll64.dll";

            if (!File.Exists(dll))
            {
                Console.WriteLine("Can't load file {0:s}", dll);
                return;
            }

            var stringOffset = ProcessQuery.VirtualAllocEx(
                dummy.hProcess,
                (IntPtr)0,
                (uint)dll.Length + 1,
                ProcessQuery.AllocationType.Commit | ProcessQuery.AllocationType.Reserve,
                ProcessQuery.MemoryProtection.ReadWrite);

            ProcessQuery.WriteProcessMemory(dummy.hProcess, stringOffset, dll, dll.Length+1, out _);
            var hThread = ProcessQuery.CreateRemoteThread(dummy.hProcess, (IntPtr)0, 0, peFile.Exports["LoadLibraryA"], (IntPtr)stringOffset, 0, out _);

            ProcessQuery.WaitForSingleObject(hThread, 0xFFFFFFFF);

            IntPtr dllHandle;
            ProcessQuery.GetExitCodeThread(hThread, out dllHandle);

            Console.WriteLine("Freeing memory at {0:x}", (ulong)stringOffset);
            ProcessQuery.VirtualFreeEx(dummy.hProcess, stringOffset, 0, ProcessQuery.AllocationType.Release);

            Console.ReadLine();

            Console.WriteLine("Unloading DLL");

            ProcessQuery.CreateRemoteThread(dummy.hProcess, (IntPtr)0, 0, (IntPtr)peFile.Exports["FreeLibrary"], dllHandle, 0, out _);
        }
    }
}
