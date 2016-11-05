/*
TO BE UPDATED!!!

https://github.com/Microsoft/dotnetsamples/blob/master/Microsoft.Diagnostics.Tracing/TraceEvent/TraceEvent/30_MonitorLoads.cs

This monstrosity uses etw to track events from "Microsoft-Windows-Kernel-Process", 
specifically process/thread/module start/stop and some accompanying data.
There are some c# API calls to query extra data (not provided by this ETW provider)
Ideally, everything would be provided by ETW, or correlation between the 2 would be 
used to check for any malicious modifications.

CMDs:
Microsoft-Windows-Kernel-Process
wevtutil get-publisher Microsoft-Windows-Kernel-Process
logman query providers Microsoft-Windows-Kernel-Process
*/

using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Management;
using System.Security.Cryptography;

namespace etwprocesses
{
    static class etwproc
    {
        static void Main(string[] args)
        {
            const bool PROCINFO = false;
            const bool SYSCALLINFO = false;

            using (TraceEventSession session = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += new ConsoleCancelEventHandler((object sender, ConsoleCancelEventArgs cancelArgs) =>
                {
                    Console.WriteLine("Control C pressed");     // Note that if you hit Ctrl-C twice rapidly you may be called concurrently.  
                    session.Dispose();                          // Note that this causes Process() to return.  
                    cancelArgs.Cancel = true;                   // This says don't abort, since Process() will return we can terminate nicely.   
                });

                session.EnableKernelProvider(KernelTraceEventParser.Keywords.ImageLoad | KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.SystemCall 
                    | KernelTraceEventParser.Keywords.FileIO | KernelTraceEventParser.Keywords.NetworkTCPIP);

                if (PROCINFO)
                {
                    // This section subscribes to DCStart events, which are automatically fed upon subscribing
                    // This allows us to enumerate every prior running process before new process data is recieved
                    #pragma warning disable CS0162 // Unreachable code detected
                    session.Source.Kernel.ProcessDCStart += delegate (ProcessTraceData data)
                    #pragma warning restore CS0162 // Unreachable code detected
                    {
                        string procPath;
                        string procVer;
                        string procDesc;
                        string parentProcPath;

                        // Attempt to enumerate process data if the process is still alive
                        // If not, we can glean more information by parsing the ETW data, but it's inconsistent
                        try
                        {
                            Process proc = Process.GetProcessById(data.ProcessID);
                            procPath = proc.MainModule.FileName;
                            procVer = proc.MainModule.FileVersionInfo.FileVersion;
                            procDesc = proc.MainModule.FileVersionInfo.FileDescription;
                        }
                        catch { procPath = procVer = procDesc = "Unknown"; }

                        // Attempt to enumerate Parent process data if the parent is still alive
                        // If not, we'd need to look back through historical data (though given this is a DCSTART event that's unlikely)
                        try
                        {
                            Process parentProc = Process.GetProcessById(data.ParentID);
                            parentProcPath = parentProc.MainModule.FileName;
                        }
                        catch { parentProcPath = "Unknown"; }

                        Console.WriteLine("[*] Currently Active Process (DCSTART)");
                        Console.WriteLine("PID: " + data.ProcessID);
                        Console.WriteLine("Name: " + data.ImageFileName);
                        Console.WriteLine("Path: " + procPath);
                        Console.WriteLine("Description: " + procDesc);
                        Console.WriteLine("Version: " + procVer);
                        Console.WriteLine("CMD line args: " + data.CommandLine);
                        Console.WriteLine("Parent PID: " + data.ParentID);
                        Console.WriteLine("Parent Path: " + parentProcPath);
                        // Useful for pausing the program inbetween each event for testing
                        //Console.ReadLine();
                        Console.WriteLine();
                    };
                }

                session.Source.Kernel.TcpIpSend += delegate (TcpIpSendTraceData data)
                {
                    foreach (var blah in data.PayloadNames)
                        Console.WriteLine(blah);
                    Console.WriteLine(data.Dump());
                };

                session.Source.Kernel.FileIOCreate += delegate (FileIOCreateTraceData data)
                {
                    foreach (var blah in data.PayloadNames)
                        Console.WriteLine(blah);
                    Console.WriteLine(data.Dump());
                };

                if (SYSCALLINFO)
                {
                    #pragma warning disable CS0162 // Unreachable code detected
                    session.Source.Kernel.PerfInfoSysClEnter += delegate (SysCallEnterTraceData data)
                    #pragma warning restore CS0162 // Unreachable code detected
                    {
                        try
                        {
                            Console.WriteLine(data.ProcessID);
                            ulong addr = data.SysCallAddress;
                            Console.WriteLine(addr);
                        
                        }
                        catch { }

                        //Console.ReadLine();
                    };
                }


                /*session.Source.Kernel.ImageLoad += delegate (ImageLoadTraceData data)
                {
                    Console.WriteLine("Process {0,16} At 0x{1,8:x} Loaded {2}", data.ProcessName, data.ImageBase, data.FileName);
                };*/

                //  Subscribe to more events (process start) 

                /*
                session.Source.Kernel.ProcessStart += delegate (ProcessTraceData data)
                {
                    Console.WriteLine("test");
                };
                */

                /*
                //  Subscribe to more events (process end)
                session.Source.Kernel.ProcessStop += delegate (ProcessTraceData data)
                {
                    Console.WriteLine("Process Ending {0,6} ", data.ProcessID);
                };
                */
                session.Source.Process();
            }
        }


        private static string getCMDLineArgs(this Process process)
        {
            var commandLine = new StringBuilder(process.MainModule.FileName);
            commandLine.Append(" ");
            string query = "SELECT CommandLine FROM Win32_Process WHERE ProcessID = ";
            using (var searcher = new ManagementObjectSearcher(query + process.Id))
            {
                foreach (var @object in searcher.Get())
                {
                    commandLine.Append(@object["CommandLine"]);
                    commandLine.Append(" ");
                }
            }
            return commandLine.ToString();
        }

        private static string getProcMD5(string path)
        {
            var md5 = MD5.Create();
            var file = File.OpenRead(path);
            return BitConverter.ToString(md5.ComputeHash(file)).Replace("-", "").ToLower();
        }

        private static string getProcSHA1(string path)
        {
            var sha1 = SHA1.Create();
            var file = File.OpenRead(path);
            return BitConverter.ToString(sha1.ComputeHash(file)).Replace("-", "").ToLower();
        }
    }
}
