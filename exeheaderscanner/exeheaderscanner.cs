using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;

namespace exeheaderscanner
{
    class exeheaderscanner
    {

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, Int64 lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);


        static void Main(string[] args)
        {
            

            foreach (Process proc in Process.GetProcesses())
            {
                try { IntPtr testhProc = proc.Handle; }
                catch { continue; }

                foreach (ProcessModule mod in proc.Modules)
                {
                    
                    bool mz = false;
                    bool pe = false;

                    if (checkMZheader(proc.Handle, (long)mod.BaseAddress))
                        mz = true;

                    if (checkPEheader(proc.Handle, (long)mod.BaseAddress))
                        pe = true;

                    if (!mz || !pe)
                    {
                        if (!mz && pe)
                            Console.WriteLine("Module {0} is missing an MZ header!", mod.FileName);
                        if (mz && !pe)
                            Console.WriteLine("Module {0} is missing a PE header!", mod.FileName);
                        if (!pe && !mz)
                            Console.WriteLine("Module {0} is missing both an MZ and PE header!", mod.FileName);
                    }


                }
            }

            
            Console.WriteLine("El fin");
            Console.ReadLine();
        }

        static bool checkMZheader(IntPtr hProc, long pageBaseAddr)
        {
            byte mz1 = 0x4d; // M
            byte mz2 = 0x5a; // Z
            int bytesRead = 0;
            byte[] buffer = new byte[2];

            ReadProcessMemory((int)hProc, pageBaseAddr, buffer, buffer.Length, ref bytesRead);
            if (buffer[0] == mz1 && buffer[1] == mz2)
                return true;


            return false;
        }

        static bool checkPEheader(IntPtr hProc, long pageBaseAddr)
        {
            byte pe1 = 0x50; // P
            byte pe2 = 0x45; // E
            long offset = pageBaseAddr;
            int bytesRead = 0;
            byte[] buffer = new byte[1024];
            int x = 0;

            // Read the processes memory at the page base address for 256 bytes
            ReadProcessMemory((int)hProc, offset, buffer, buffer.Length, ref bytesRead);

            // Loop through each of the bytes looking for the PE header
            // (There's probably a more efficient way to do this, but nothing beats a good ol' while loop)
            while (x < 1023)
            {
                if (buffer[x] == pe1 && buffer[x + 1] == pe2)
                    return true;
                x++;
            }

            return false;
        }
    }
}
