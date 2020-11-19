using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace H4xbr1x
{
    public class InjectedDll
    {
        Process process = default;
        IntPtr handle = default;
        IntPtr stringoffset = default;
        IPeFile pefile = default;
        bool injected = false;
        string filename = default;

        public InjectedDll(string filename, Process process)
        {
            this.filename = filename;
            this.process = process;
        }
        public void Inject()
        {
            if (injected)
                return;

            Console.WriteLine("Process {0:s}", process.processEntry.szExeFile);
            var dllname = "kernel32.dll";
            var modules = ProcessQuery.GetModuleList(process);
            ProcessQuery.MODULEENTRY32 me = ProcessQuery.GetModuleByName(process, dllname);
            Console.WriteLine("kernel32 dll name: {0:s}", me.szModule);
            pefile = PeParser.ParseFromProcess(process, me.modBaseAddr);
            Console.WriteLine("Base address of kernel32.dll: {0:x}", (ulong)me.modBaseAddr);
            Console.WriteLine("Dos signature: {0:x}", pefile.DosHeader.e_magic);
            Console.WriteLine("Function names stored at {0:x}", pefile.ExportDirectory.AddressOfNames);
            Console.WriteLine("Function addresses stored at {0:x}", pefile.ExportDirectory.AddressOfFunctions);
            Console.WriteLine("Function ordinals stored at {0:x}", pefile.ExportDirectory.AddressOfNameOrdinals);
            Console.WriteLine("Ordinal base: {0:d}", pefile.ExportDirectory.Base);
            Console.WriteLine("LoadLibraryA offset: {0:x}", (ulong)pefile.Exports["LoadLibraryA"]);
            Console.WriteLine("GetModuleHandleA offset: {0:x}", (ulong)pefile.Exports["GetModuleHandleA"]);
            Console.WriteLine("GetModuleHandleW offset: {0:x}", (ulong)pefile.Exports["GetModuleHandleW"]);

            //return;

            // let's try injecting a dll

            if (!File.Exists(filename))
            {
                Console.WriteLine("Can't load file {0:s}", filename);
                return;
            }

            stringoffset = ProcessQuery.VirtualAllocEx(
                process.hProcess,
                (IntPtr)0,
                (uint)filename.Length + 1,
                ProcessQuery.AllocationType.Commit | ProcessQuery.AllocationType.Reserve,
                ProcessQuery.MemoryProtection.ReadWrite);

            ProcessQuery.WriteProcessMemory(process.hProcess, stringoffset, filename, filename.Length + 1, out _);
            var hThread = ProcessQuery.CreateRemoteThread(process.hProcess, (IntPtr)0, 0, pefile.Exports["LoadLibraryA"], (IntPtr)stringoffset, 0, out _);

            ProcessQuery.WaitForSingleObject(hThread, 0xFFFFFFFF);

            ProcessQuery.GetExitCodeThread(hThread, out handle);

            Console.WriteLine("Freeing memory at {0:x}", (ulong)stringoffset);
            ProcessQuery.VirtualFreeEx(process.hProcess, stringoffset, 0, ProcessQuery.AllocationType.Release);

            injected = true;
            return;
        }

        public void UnInject()
        {
            if (!injected)
                return;

            var hThread = ProcessQuery.CreateRemoteThread(process.hProcess, (IntPtr)0, 0, (IntPtr)pefile.Exports["FreeLibrary"], handle, 0, out _);

            ProcessQuery.WaitForSingleObject(hThread, 0xFFFFFFFF);

            injected = false;
        }
    }
}
