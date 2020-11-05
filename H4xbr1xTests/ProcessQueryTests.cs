using System;
using Xunit;
using H4xbr1x;
using System.Linq;

namespace H4xbr1xTests
{
    public class ProcessQueryTests
    {
        [Fact]
        public void TestCanOpenBasicWindow32()
        {
            // use BasicWindow32.exe as our victim
            // make sure it's already running
            Process notepad = ProcessQuery.OpenProcessByName("BasicWindow32.exe");
            Assert.False(notepad.Equals(default));
            Assert.Equal("BasicWindow32.exe", notepad.processEntry.szExeFile);
        }

        [Fact]
        public void TestCanGetKernel32ModuleHandle32()
        {
            // use BasicWindow32.exe as our victim
            // make sure it's already running
            Process notepad = ProcessQuery.OpenProcessByName("BasicWindow32.exe");
            Assert.False(notepad.Equals(default));
            Assert.Equal("BasicWindow32.exe", notepad.processEntry.szExeFile);
            var dllname = "kernel32.dll";
            var modules = ProcessQuery.GetModuleList(notepad);
            ProcessQuery.MODULEENTRY32 me = ProcessQuery.GetModuleByName(notepad, dllname);
            Assert.True(!me.Equals(default));
            Assert.Equal("KERNEL32.DLL", me.szModule);
        }

        [Fact]
        public void TestCanGetKernel32Headers32()
        {
            // use BasicWindow32.exe as our victim
            // make sure it's already running
            Process notepad = ProcessQuery.OpenProcessByName("BasicWindow32.exe");
            Assert.False(notepad.Equals(default));
            Assert.Equal("BasicWindow32.exe", notepad.processEntry.szExeFile);
            var dllname = "kernel32.dll";
            var modules = ProcessQuery.GetModuleList(notepad);
            ProcessQuery.MODULEENTRY32 me = ProcessQuery.GetModuleByName(notepad, dllname);
            Assert.True(!me.Equals(default));
            Assert.Equal("KERNEL32.DLL", me.szModule);

        }
    }
}
