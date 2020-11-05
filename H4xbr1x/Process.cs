using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace H4xbr1x
{
    public class Process : IDisposable
    {
        private bool disposed = false;

        public IntPtr hProcess { get; set; }
        public List<ProcessQuery.MEMORY_BASIC_INFORMATION64> MemoryInformationBlocks = new List<ProcessQuery.MEMORY_BASIC_INFORMATION64>();
        public List<IntPtr> ScanResults = new List<IntPtr>();
        public ProcessQuery.PROCESSENTRY32 processEntry { get; set; }

        public Process(ProcessQuery.PROCESSENTRY32 processEntry)
        {
            this.processEntry = processEntry;
            hProcess = ProcessQuery.OpenProcess(ProcessQuery.ProcessAccessFlags.All, false, processEntry.th32ProcessID);
        }

        public void Dispose()
        {
            Dispose(true);

            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                ProcessQuery.CloseHandle(hProcess);
                hProcess = default;
                disposed = true;
            }
        }

        ~Process()
        {
            Dispose(false);
        }

        public void GetMemoryAllocations()
        {
            MemoryInformationBlocks = new List<ProcessQuery.MEMORY_BASIC_INFORMATION64>();
            IntPtr basePtr = IntPtr.Zero;
            var mbi = new ProcessQuery.MEMORY_BASIC_INFORMATION64();
            while (0 != ProcessQuery.VirtualQueryEx(hProcess, basePtr, out mbi, (uint)Marshal.SizeOf(mbi)))
            {
                if (mbi.State == ProcessQuery.MbiStateFlags.Commit)
                {
                    MemoryInformationBlocks.Add(mbi);
                }
                basePtr = new IntPtr(basePtr.ToInt64() + (long)mbi.RegionSize);
                if (basePtr.Equals(0))
                    break;
            }
        }

        public IEnumerable<IntPtr> ScanRegion(IntPtr baseAddress, ulong regionSize, float value)
        {
            var buffer = new float[regionSize / sizeof(float)];
            var offsets = new List<IntPtr>();

            ProcessQuery.ReadProcessMemory(hProcess, baseAddress, buffer, (IntPtr)regionSize, out IntPtr numBytesRead);

            for (long offset = 0; offset < (long)numBytesRead / sizeof(float); offset++)
            {
                var calculatedOffset = (long)baseAddress + (offset * sizeof(float));
                if (value == buffer[offset])
                {
                    offsets.Add(new IntPtr(calculatedOffset));
                }
            }

            return offsets;
        }

        public IEnumerable<IntPtr> ScanFirst(float value)
        {
            ScanResults = new List<IntPtr>();
            foreach (var mbi in MemoryInformationBlocks)
            {
                var results = ScanRegion((IntPtr)mbi.BaseAddress, mbi.RegionSize, value);
                ScanResults.AddRange(results);
            }

            Console.WriteLine("Total results: {0:d}", ScanResults.Count());

            return ScanResults;
        }

        public IEnumerable<IntPtr> ScanNext(float value)
        {
            var newScanResults = new List<IntPtr>();
            foreach (var address in ScanResults)
            {
                var results = ScanRegion(address, sizeof(float), value);
                newScanResults.AddRange(results);
            }

            ScanResults = newScanResults;

            Console.WriteLine("Total results: {0:d}", ScanResults.Count());

            return ScanResults;
        }
    }
}
