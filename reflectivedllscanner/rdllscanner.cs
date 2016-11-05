// Reflective DLL injection scanner - Matt Watkins / Countercept
// If you're new to c#, jump to line 123 - that's where everything kicks off :)

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Management;
using System.ComponentModel;

namespace reflectivedllscanner
{
    class rdllscanner
    {
        [DllImport("kernel32.dll")]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, Int64 lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQueryInformationThread(IntPtr threadHandle, ThreadInfoClass threadInformationClass, IntPtr threadInformation,
                int threadInformationLength, IntPtr returnLengthPtr);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern uint GetMappedFileName(IntPtr m_hProcess, IntPtr lpv, StringBuilder lpFilename, uint nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccess processAccess, bool bInheritHandle, int processId);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [Flags]
        public enum ThreadAccess : int
        {
            Terminate = 0x0001,
            SuspendResume = 0x0002,
            GetContext = 0x0008,
            SetContext = 0x0010,
            SetInformation = 0x0020,
            QueryInformation = 0x0040,
            SetThreadToken = 0x0080,
            Impersonate = 0x0100,
            DirectImpersonation = 0x0200
        }

        public enum ProcessAccess
        {
        }

        public enum AllocationProtect : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400,
            UNKNOWN = 0x0
        }

        public enum State : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000,
            UNKNOWN = 0x0
        }

        public enum Protect : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400,
            UNKNOWN = 0x0
        }

        public enum Type : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000,
            UNKNOWN = 0x0
        }

        public enum ThreadInfoClass : int
        {
            ThreadQuerySetWin32StartAddress = 9
        }

        static void Main(string[] args)
        {
            // Let's jump straight in... Loop through each and every process on the box!
            foreach (Process proc in Process.GetProcesses())
            {
                // Slightly hacky. Let's test if we can get a handle on this process. If not, let's skip this process!
                // Running VS15 as admin allows most handles, but not SYSTEM etc. Alternatively, run as SYSTEM (like DQT)
                try
                {
                    IntPtr testhProc = proc.Handle;
                }
                catch
                {
                    continue;
                }

                // Obtain a handle to the process in question
                IntPtr hProc = proc.Handle;

                long MaxAddress = 0x7fffffffffffffff;
                long address = 0;
                MEMORY_BASIC_INFORMATION p;

                do
                {
                    // First we use VirtualQueryEx to query for each page within the processes virtual address space
                    // We incremenent the address each time with the prior endaddress +1 and loop through each of the pages
                    // If the return value is greater than 1 that indicates another page exists.
                    // A return value of 0 implies the page doesn't exist, suggesting there are no more pages available
                    if (VirtualQueryEx(hProc, (IntPtr)address, out p, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0)
                        break;

                    long pageBaseAddr = (long)p.BaseAddress;
                    long pageEndAddr = ((long)p.BaseAddress + (long)p.RegionSize - 1);

                    // *Debugging section*
                    // Prints each page region addresses with corresponding information 
                    /*
                    Console.WriteLine("Address Range: {0} - {1}", pageBaseAddr, pageEndAddr);
                    Console.WriteLine("Address Range: {0:x} - {1:x}", pageBaseAddr, pageEndAddr);
                    Console.WriteLine("Protect: " + (Protect)m.Protect);
                    Console.WriteLine("Alloc Protect: " + (AllocationProtect)m.AllocationProtect);
                    Console.WriteLine("State: " + (State)m.State);
                    Console.WriteLine("Type: " + (Type)m.Type);
                    Console.WriteLine(); 
                    */

                    // Now we enumerate through each of the loaded modules
                    // A system loaded module looks like (LoadLibrary):
                    //      Protect: PAGE_READONLY
                    //      Allocated Protect: PAGE_EXECUTE_WRITECOPY
                    //      Type: MEM_IMAGE
                    //      State: MEM_COMMIT
                    // BUT, this is fairly trivial to get right, so we'll stick to pages without a corresponding module for now
                    // (This might be something to look for standard LoadLibrary injections...
                    // TL;DR Check for pages with a corresponding loaded module at the same base address 

                    bool found = false;

                    foreach (ProcessModule mod in proc.Modules)
                    {
                        if ((long)mod.BaseAddress == pageBaseAddr)
                            found = true;
                    }

                    // Here we are interested in pages which don't have an associated module. (As checked above)
                    // We can now apply whatever checks we want to identify injected code. (Given there is no loaded module, there shouldn't be any)
                    if (found == false)
                    {
                        bool suspicious = false;
                        bool mz = false;
                        bool pe = false;
                        bool thread = false;
                        StringBuilder fn = new StringBuilder(250);

                        // First up is the MZ header check
                        if (checkMZheader(hProc, pageBaseAddr))
                        {
                            mz = true;
                            suspicious = true;
                        }

                        // We're also interested in any PE headers
                        if (checkPEheader(hProc, pageBaseAddr))
                        {
                            pe = true;
                            suspicious = true;
                        }

                        // Check if there are any corresponding threads
                        if (checkThreads(proc, pageBaseAddr, pageEndAddr))
                        {
                            thread = true;
                            suspicious = true;
                        }

                        // Check the page has executable permissions
                        if (!(p.Protect == 0x10 || p.Protect == 0x20 || p.Protect == 0x40 || p.Protect == 0x80))
                        {
                            suspicious = false;
                        }

                        // Check for a page mapping (Are there any files mapped into the page in question)
                        if ((checkMappedFile(proc.Id, (IntPtr)pageBaseAddr, ref fn)) & suspicious)
                        {
                            // There's a mapped file so we're not interested (A reflective load can't have a mapped file as it must exist on disk)
                            // Leaving below in for debugging/clarity 
                            //Console.WriteLine("Base Address: {0:x}", pageBaseAddr);
                            //Console.WriteLine("Mapped file: {0}", fn);
                            suspicious = false;
                        }

                        // The above checks determine whether the page is suspicious or not
                        // We COULD check the permissions/file mappings first and skip if found, but we might want to change this at a later point

                        if (suspicious)
                        {
                            Console.WriteLine("PID: {0} / Process Name: {1}", proc.Id, proc.ProcessName);
                            Console.WriteLine("Base Address: {0:x}", pageBaseAddr);
                            Console.WriteLine("[+] Protect: {0}", (Protect)p.Protect);
                            if (mz)
                                Console.WriteLine("[+] MZ Header Found");
                            if (pe)
                                Console.WriteLine("[+] PE Header Found");
                            if (thread)
                                Console.WriteLine("[+] Thread Found");
                            Console.WriteLine();
                        }
                    }

                    //Increment the address value to get the next page on the following loop
                    address = pageEndAddr + 1;
                }
                while (address < MaxAddress);
            }
            Console.WriteLine("That's all folks...");
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
            byte[] buffer = new byte[256];
            int x = 0;

            // Read the processes memory at the page base address for 256 bytes
            ReadProcessMemory((int)hProc, offset, buffer, buffer.Length, ref bytesRead);

            // Loop through each of the bytes looking for the PE header
            // (There's probably a more efficient way to do this, but nothing beats a good ol' while loop)
            while (x < 255)
            {
                if (buffer[x] == pe1 && buffer[x + 1] == pe2)
                    return true;
                x++;
            }

            return false;
        }

        static bool checkThreads(Process proc, long pageBaseAddr, long pageEndAddr)
        {
            // Loop through each of the threads 
            foreach (ProcessThread thread in proc.Threads)
            {
                long threadBaseAddr = (long)GetThreadStartAddress(thread.Id);

                // Check if the threads base address falls within the pages memory space 
                if ((pageBaseAddr - threadBaseAddr <= 0) && (pageEndAddr - threadBaseAddr >= 0))
                    return true;
            }
            return false;
        }

        static bool checkMappedFile(int pid, IntPtr pMem, ref StringBuilder fn)
        {
            // To use GetMappedFileName, we need a handle with higher privileges than a normal handle
            IntPtr hProc = OpenProcess((ProcessAccess)0x0410, false, pid);

            // Check if a mapped file exists for the page in question
            if (GetMappedFileName(hProc, pMem, fn, 250) > 0)
            {
                //Console.WriteLine("[+] Mapped file for address {0}", fn);
                CloseHandle(hProc);
                return true;
            }
            //Console.WriteLine("[-] No mapped file for address");
            CloseHandle(hProc);
            return false;
        }

        static IntPtr GetThreadStartAddress(int threadId)
        {
            // As above, we need higher privileges than a normal thread handle.
            var hThread = OpenThread(ThreadAccess.QueryInformation, false, threadId);
            if (hThread == IntPtr.Zero)
                return (IntPtr)0;

            var buf = Marshal.AllocHGlobal(IntPtr.Size);

            var result = NtQueryInformationThread(hThread, ThreadInfoClass.ThreadQuerySetWin32StartAddress, buf, IntPtr.Size, IntPtr.Zero);
            if (result != 0)
            {
                CloseHandle(hThread);
                Marshal.FreeHGlobal(buf);
                return (IntPtr)0;
            }

            CloseHandle(hThread);
            Marshal.FreeHGlobal(buf);
            return Marshal.ReadIntPtr(buf);
        }
    }
}
