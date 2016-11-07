#pragma warning disable CS0162
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
            bool PREPROCINFO = false;
            bool PRETHREADINFO = false;
            bool PREIMAGEINFO = false;
            bool PROCINFO = false;
            bool THREADINFO = false;
            bool IMAGEINFO = true;
            bool NETWORKTRACEINFO = false;
            bool SYSCALLINFO = false;
            bool ALLEVENTS = false;

            if (ALLEVENTS)
                PREPROCINFO = PREIMAGEINFO = PRETHREADINFO = PROCINFO = THREADINFO = NETWORKTRACEINFO = true;

            string procPath;
            string procVer;
            string procDesc;
            string procName;
            string procMD5;
            string procSHA1;
            string parentProcPath;

            using (TraceEventSession session = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += new ConsoleCancelEventHandler((object sender, ConsoleCancelEventArgs cancelArgs) =>
                {
                    Console.WriteLine("Control C pressed");     // Note that if you hit Ctrl-C twice rapidly you may be called concurrently.  
                    session.Dispose();                          // Note that this causes Process() to return.  
                    cancelArgs.Cancel = true;                   // This says don't abort, since Process() will return we can terminate nicely.   
                });

                session.EnableKernelProvider(KernelTraceEventParser.Keywords.ImageLoad |
                    KernelTraceEventParser.Keywords.Process |
                    KernelTraceEventParser.Keywords.SystemCall |
                    KernelTraceEventParser.Keywords.FileIO |
                    KernelTraceEventParser.Keywords.NetworkTCPIP);

                // ProcessDCStart Events - All processes active prior to running the trace
                if (PREPROCINFO)
                {

                    session.Source.Kernel.ProcessDCStart += delegate (ProcessTraceData data)
                    {
                        // Attempt to enumerate process data if the process is still alive
                        try
                        {
                            Process proc = Process.GetProcessById(data.ProcessID);
                            procPath = proc.MainModule.FileName;
                            procVer = proc.MainModule.FileVersionInfo.FileVersion;
                            procDesc = proc.MainModule.FileVersionInfo.FileDescription;
                            procMD5 = getProcMD5(procPath);
                            procSHA1 = getProcSHA1(procPath);
                        }
                        catch { procPath = procVer = procDesc = procMD5 = procSHA1 = "Unknown"; }

                        // Attempt to enumerate Parent process data if the parent is still alive
                        try
                        {
                            Process parentProc = Process.GetProcessById(data.ParentID);
                            parentProcPath = parentProc.MainModule.FileName;
                        }
                        catch { parentProcPath = "Unknown"; }

                        Console.WriteLine("[+] Prior Process Start Event ({0})", data.TimeStamp);
                        Console.WriteLine("PID: " + data.ProcessID);
                        Console.WriteLine("Name: " + data.ImageFileName);
                        Console.WriteLine("Path: " + procPath);
                        Console.WriteLine("Description: " + procDesc);
                        Console.WriteLine("Version: " + procVer);
                        Console.WriteLine("MD5: " + procMD5);
                        Console.WriteLine("SHA1: " + procSHA1);
                        Console.WriteLine("CMD line args: " + data.CommandLine);
                        Console.WriteLine("Parent PID: " + data.ParentID);
                        Console.WriteLine("Parent Path: " + parentProcPath);
                        Console.WriteLine();
                    };
                }

                // Realtime thread tracing
                if (PRETHREADINFO)
                {
                    session.Source.Kernel.ThreadDCStart += delegate (ThreadTraceData data)
                    {
                        // Attempt to enumerate process data if the process is still alive
                        try
                        {
                            Process proc = Process.GetProcessById(data.ProcessID);
                            procPath = proc.MainModule.FileName;
                            procVer = proc.MainModule.FileVersionInfo.FileVersion;
                            procDesc = proc.MainModule.FileVersionInfo.FileDescription;
                        }
                        catch { procPath = procVer = procDesc = "Unknown"; }

                        Console.WriteLine("[+] Prior Thread Start Event ({0})", data.TimeStamp);
                        Console.WriteLine("Path: " + procPath);
                        Console.WriteLine("PID: " + data.ProcessID);
                        Console.WriteLine("TID: " + data.ThreadID);
                        Console.WriteLine("Description: " + procDesc);
                        Console.WriteLine("Version: " + procVer);
                        Console.WriteLine("Win32 Start Address: {0:x}", data.Win32StartAddr);
                        Console.WriteLine();

                    };
                }

                if (PREIMAGEINFO)
                {
                    session.Source.Kernel.ImageDCStart += delegate (ImageLoadTraceData data)
                    {
                        // Attempt to enumerate process data if the process is still alive
                        try
                        {
                            Process proc = Process.GetProcessById(data.ProcessID);
                            procPath = proc.MainModule.FileName;
                            procVer = proc.MainModule.FileVersionInfo.FileVersion;
                            procDesc = proc.MainModule.FileVersionInfo.FileDescription;
                        }
                        catch { procPath = procVer = procDesc = "Unknown"; }

                        Console.WriteLine("[+] Prior Image Start Event ({0})", data.TimeStamp);
                        Console.WriteLine("Process: " + data.ProcessName);
                        Console.WriteLine("Path: " + procPath);
                        Console.WriteLine("PID: " + data.ProcessID);
                        Console.WriteLine("Description: " + procDesc);
                        Console.WriteLine("Version: " + procVer);
                        Console.WriteLine("TID: " + data.ThreadID);
                        Console.WriteLine("Module Path: " + data.FileName);
                        Console.WriteLine("Module Base Address: 0x{0:x}", data.PayloadByName("ImageBase"));
                        Console.WriteLine("Module Size: 0x{0:x}", data.ImageSize);
                        Console.WriteLine();
                    };
                }

                // ProcessStart & ProcessStop events
                if (PROCINFO)
                {
                    session.Source.Kernel.ProcessStart += delegate (ProcessTraceData data)
                    {
                        // Attempt to enumerate process data if the process is still alive
                        try
                        {
                            Process proc = Process.GetProcessById(data.ProcessID);
                            procPath = proc.MainModule.FileName;
                            procVer = proc.MainModule.FileVersionInfo.FileVersion;
                            procDesc = proc.MainModule.FileVersionInfo.FileDescription;
                            procMD5 = getProcMD5(procPath);
                            procSHA1 = getProcSHA1(procPath);
                        }
                        catch { procPath = procVer = procDesc = procMD5 = procSHA1 = "Unknown"; }

                        // Attempt to enumerate Parent process data if the parent is still alive
                        try
                        {
                            Process parentProc = Process.GetProcessById(data.ParentID);
                            parentProcPath = parentProc.MainModule.FileName;
                        }
                        catch { parentProcPath = "Unknown"; }

                        Console.WriteLine("[+] Process Start Event ({0})", data.TimeStamp);
                        Console.WriteLine("PID: " + data.ProcessID);
                        Console.WriteLine("Name: " + data.ImageFileName);
                        Console.WriteLine("Path: " + procPath);
                        Console.WriteLine("Description: " + procDesc);
                        Console.WriteLine("Version: " + procVer);
                        Console.WriteLine("MD5: " + procMD5);
                        Console.WriteLine("SHA1: " + procSHA1);
                        Console.WriteLine("CMD line args: " + data.CommandLine);
                        Console.WriteLine("Parent PID: " + data.ParentID);
                        Console.WriteLine("Parent Path: " + parentProcPath);
                        Console.WriteLine();
                    };

                    session.Source.Kernel.ProcessStop += delegate (ProcessTraceData data)
                    {
                        // Attempt to enumerate Parent process data if the parent is still alive
                        try
                        {
                            Process parentProc = Process.GetProcessById(data.ParentID);
                            parentProcPath = parentProc.MainModule.FileName;
                        }
                        catch { parentProcPath = "Unknown"; }

                        Console.WriteLine("[+] Process Stop Event ({0})", data.TimeStamp);
                        Console.WriteLine("PID: " + data.ProcessID);
                        Console.WriteLine("Name: " + data.ImageFileName);
                        Console.WriteLine("CMD line args: " + data.CommandLine);
                        Console.WriteLine("Parent PID: " + data.ParentID);
                        Console.WriteLine("Parent Path: " + parentProcPath);
                        Console.WriteLine();
                    };
                }

                // Realtime thread tracing
                if (THREADINFO)
                {
                    session.Source.Kernel.ThreadStart += delegate (ThreadTraceData data)
                    {
                        // Attempt to enumerate process data if the process is still alive
                        try
                        {
                            Process proc = Process.GetProcessById(data.ProcessID);
                            procPath = proc.MainModule.FileName;
                            procVer = proc.MainModule.FileVersionInfo.FileVersion;
                            procDesc = proc.MainModule.FileVersionInfo.FileDescription;
                        }
                        catch { procPath = procVer = procDesc = "Unknown"; }

                        Console.WriteLine("[+] Thread Start Event ({0})", data.TimeStamp);
                        Console.WriteLine("Path: " + procPath);
                        Console.WriteLine("PID: " + data.ProcessID);
                        Console.WriteLine("TID: " + data.ThreadID);
                        Console.WriteLine("Description: " + procDesc);
                        Console.WriteLine("Version: " + procVer);
                        Console.WriteLine("Win32 Start Address: {0:x}", data.Win32StartAddr);
                        Console.WriteLine();
                    };

                    session.Source.Kernel.ThreadStop += delegate (ThreadTraceData data)
                    {
                        // Attempt to enumerate process data if the process is still alive
                        try
                        {
                            Process proc = Process.GetProcessById(data.ProcessID);
                            procPath = proc.MainModule.FileName;
                            procVer = proc.MainModule.FileVersionInfo.FileVersion;
                            procDesc = proc.MainModule.FileVersionInfo.FileDescription;
                        }
                        catch { procPath = procVer = procDesc = "Unknown"; }

                        Console.WriteLine("[+] Thread Stop Event ({0})", data.TimeStamp);
                        Console.WriteLine("Path: " + procPath);
                        Console.WriteLine("PID: " + data.ProcessID);
                        Console.WriteLine("TID: " + data.ThreadID);
                        Console.WriteLine("Description: " + procDesc);
                        Console.WriteLine("Version: " + procVer);
                        Console.WriteLine("Win32 Start Address: {0:x}", data.Win32StartAddr);
                        Console.WriteLine();
                    };
                }

                if (IMAGEINFO)
                {
                    session.Source.Kernel.ImageLoad += delegate (ImageLoadTraceData data)
                    {
                        // Attempt to enumerate process data if the process is still alive
                        try
                        {
                            Process proc = Process.GetProcessById(data.ProcessID);
                            procPath = proc.MainModule.FileName;
                            procVer = proc.MainModule.FileVersionInfo.FileVersion;
                            procDesc = proc.MainModule.FileVersionInfo.FileDescription;
                        }
                        catch { procPath = procVer = procDesc = "Unknown"; }

                        Console.WriteLine("[+] Image Load Event ({0})", data.TimeStamp);
                        Console.WriteLine("Process: " + data.ProcessName);
                        Console.WriteLine("Path: " + procPath);
                        Console.WriteLine("PID: " + data.ProcessID);
                        Console.WriteLine("Description: " + procDesc);
                        Console.WriteLine("Version: " + procVer);
                        Console.WriteLine("TID: " + data.ThreadID);
                        Console.WriteLine("Module Path: " + data.FileName);
                        Console.WriteLine("Module Base Address: 0x{0:x}", data.PayloadByName("ImageBase"));
                        Console.WriteLine("Module Size: 0x{0:x}", data.ImageSize);
                        Console.WriteLine("Module MD5: " + getProcMD5(data.FileName));
                        Console.WriteLine("Module SHA1: " + getProcSHA1(data.FileName));
                        Console.WriteLine();
                    };

                    session.Source.Kernel.ImageUnload += delegate (ImageLoadTraceData data)
                    {
                        // Attempt to enumerate process data if the process is still alive
                        try
                        {
                            Process proc = Process.GetProcessById(data.ProcessID);
                            procPath = proc.MainModule.FileName;
                            procVer = proc.MainModule.FileVersionInfo.FileVersion;
                            procDesc = proc.MainModule.FileVersionInfo.FileDescription;
                        }
                        catch { procPath = procVer = procDesc = "Unknown"; }

                        Console.WriteLine("[+] Image Unload Event ({0})", data.TimeStamp);
                        Console.WriteLine("Process: " + data.ProcessName);
                        Console.WriteLine("Path: " + procPath);
                        Console.WriteLine("PID: " + data.ProcessID);
                        Console.WriteLine("Description: " + procDesc);
                        Console.WriteLine("Version: " + procVer);
                        Console.WriteLine("Module Path: " + data.FileName);
                        Console.WriteLine("Module Base Address: 0x{0:x}", data.PayloadByName("ImageBase"));
                        Console.WriteLine("Module Size: 0x{0:x}", data.ImageSize);
                        Console.WriteLine("Module MD5: " + getProcMD5(data.FileName));
                        Console.WriteLine("Module SHA1: " + getProcSHA1(data.FileName));
                        Console.WriteLine();
                    };
                }

                // Realtime process network tracing
                if (NETWORKTRACEINFO)
                {
                    session.Source.Kernel.TcpIpSend += delegate (TcpIpSendTraceData data)
                    {
                        // Attempt to enumerate process/parent data if the process is still alive
                        try
                        {
                            Process proc = Process.GetProcessById(data.ProcessID);
                            procPath = proc.MainModule.FileName;
                            procName = proc.ProcessName;
                            procVer = proc.MainModule.FileVersionInfo.FileVersion;
                            procDesc = proc.MainModule.FileVersionInfo.FileDescription;
                        }
                        catch
                        {
                            procPath = procVer = procDesc = procName = "Unknown";
                        }

                        Console.WriteLine("[+] Process Network Event - TCP/IP Send ({0})", data.TimeStamp);
                        Console.WriteLine("PID: " + data.ProcessID);
                        Console.WriteLine("Name: " + procName);
                        Console.WriteLine("Path: " + procPath);
                        Console.WriteLine("Description: " + procDesc);
                        Console.WriteLine("Version: " + procVer);
                        //Console.WriteLine("CMD line args: " + data.CommandLine);
                        Console.WriteLine("Source: {0}:{1}", data.saddr, data.sport);
                        Console.WriteLine("Destination: {0}:{1}", data.daddr, data.dport);
                        Console.WriteLine();
                    };

                    session.Source.Kernel.TcpIpConnect += delegate (TcpIpConnectTraceData data)
                    {
                        // Attempt to enumerate process/parent data if the process is still alive
                        try
                        {
                            Process proc = Process.GetProcessById(data.ProcessID);
                            procPath = proc.MainModule.FileName;
                            procName = proc.ProcessName;
                            procVer = proc.MainModule.FileVersionInfo.FileVersion;
                            procDesc = proc.MainModule.FileVersionInfo.FileDescription;
                        }
                        catch
                        {
                            procPath = procVer = procDesc = procName = "Unknown";
                        }

                        Console.WriteLine("[+] Process Network Event - TCP/IP Connect ({0})", data.TimeStamp);
                        Console.WriteLine("PID: " + data.ProcessID);
                        Console.WriteLine("Name: " + procName);
                        Console.WriteLine("Path: " + procPath);
                        Console.WriteLine("Description: " + procDesc);
                        Console.WriteLine("Version: " + procVer);
                        //Console.WriteLine("CMD line args: " + data.CommandLine);
                        Console.WriteLine("Source: {0}:{1}", data.saddr, data.sport);
                        Console.WriteLine("Destination: {0}:{1}", data.daddr, data.dport);
                        Console.WriteLine();
                    };

                }
                
                if (SYSCALLINFO)
                {
                    session.Source.Kernel.PerfInfoSysClEnter += delegate (SysCallEnterTraceData data)
                    {
                        try
                        {
                            Console.WriteLine(data.ThreadID);
                            if (data.ProcessID > 0)
                                Console.WriteLine(data.SysCallAddress.ToString("X"));
                        }
                        catch { }


                    };
                }

                /*
                session.Source.Kernel.FileIOCreate += delegate (FileIOCreateTraceData data)
                {
                    foreach (var blah in data.PayloadNames)
                        Console.WriteLine(blah);
                    Console.WriteLine(data.Dump());
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
