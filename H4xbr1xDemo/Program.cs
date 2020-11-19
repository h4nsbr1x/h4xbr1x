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

            var dll = new InjectedDll("C:\\Users\\User\\source\\repos\\H4xbr1x\\H4xbr1xDemo\\hl1dll32.dll", dummy);

            dll.Inject();

            Console.ReadLine();

            Console.WriteLine("Unloading DLL");

            dll.UnInject();
        }
    }
}
