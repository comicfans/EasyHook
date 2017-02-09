using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using EasyHook;

namespace FileMonInject
{
    public class Main : EasyHook.IEntryPoint
    {
        FileMon.FileMonInterface Interface;
        LocalHook CreateFileHook;
        LocalHook OpenFileHook;

        LocalHook ReadFileHook;
        Stack<String> Queue = new Stack<String>();
        Stack<String> oqueue = new Stack<String>();

        public Main(
            RemoteHooking.IContext InContext,
            String InChannelName)
        {
            // connect to host...
            Interface = RemoteHooking.IpcConnectClient<FileMon.FileMonInterface>(InChannelName);

            Interface.Ping();
        }

        public void Run(
            RemoteHooking.IContext InContext,
            String InChannelName)
        {
            // install hook...
            try
            {

                CreateFileHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
                    new DCreateFile(CreateFile_Hooked),
                    this);

                OpenFileHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "OpenFile"),
                    new DOpenFile(OpenFile_Hooked), this);

                ReadFileHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "ReadFile"),
                    new DReadFile(ReadFileHooked), this);

                LocalHook fopenHook = LocalHook.Create(
                    LocalHook.GetProcAddress("api-ms-win-crt-stdio-l1-1-0.dll", "fopen"),
                    new Dfopen(fopen_hooked), this);

                LocalHook _wfsopenHook = LocalHook.Create
                    (LocalHook.GetProcAddress("api-ms-win-crt-stdio-l1-1-0.dll", "_wfsopen"),
                    new D_wfsopen(_wfsopen_hooked), this);

                LocalHook fopen_sHook = LocalHook.Create(
                    LocalHook.GetProcAddress("api-ms-win-crt-stdio-l1-1-0.dll", "fopen_s"),
                    new D_fopen_s(fopen_s_hooked), this);

                LocalHook _wfopen_sHook = LocalHook.Create(
                    LocalHook.GetProcAddress("api-ms-win-crt-stdio-l1-1-0.dll", "_wfopen_s"),
                    new D_wfopen_s(_wfopen_s_hooked), this);

                //LocalHook createProcessHook = LocalHook.Create(
                 //   LocalHook.GetProcAddress("kernel32.dll", "CreateProcessW"), new DCreateProcess(CreateProcessHooked), this);

                LocalHook readfileexHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "ReadFile"), new DReadFileEx(ReadFileExHooked), this);

                LocalHook createfilemapHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "CreateFileMappingW"), new DCreateFileMapping(CreateFileMappingHooked), this);

                LocalHook loadLibrarywHook = LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "LoadLibraryW"), new DLoadLibraryW(LoadLibraryWHooked), this);
                LocalHook loadLibraryaHook = LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "LoadLibraryA"), new DLoadLibraryW(LoadLibraryAHooked), this);

                LocalHook loadLibraryExWHook = LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "LoadLibraryExW"), new DLoadLibraryExW(LoadLibraryExWHooked), this);
                LocalHook wsopen_sHook= LocalHook.Create(LocalHook.GetProcAddress("api-ms-win-crt-stdio-l1-1-0.dll", "_wsopen_s"), new Dwsopen_s(wsopen_sHooked), this);

                LocalHook FindFirstFileWHook = LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "FindFirstFileW"), new DFindFirstFileW(FindFirstFileWHooked), this);

                LocalHook GetFileAttributesExWHook = LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "GetFileAttributesExW"), new DGetFileAttributesExW(GetFileAttributesExWHooked),this);

                LocalHook wfreopenHook = LocalHook.Create(LocalHook.GetProcAddress("api-ms-win-crt-stdio-l1-1-0.dll", "_wfreopen_s"), new D_wfreopen_s(_wfreopen_sHooked), this);

                LocalHook _waccess_sHook= LocalHook.Create(LocalHook.GetProcAddress("api-ms-win-crt-filesystem-l1-1-0.dll", "_waccess_s"), new D_waccess_s(_waccess_sHooked), this);
                LocalHook _wstat64i32Hook= LocalHook.Create(LocalHook.GetProcAddress("api-ms-win-crt-filesystem-l1-1-0.dll", "_wstat64i32"), new D_wstat64i32(_wstat64i32Hooked), this);

                //LocalHook NtQueryDirectoryObjectHook = LocalHook.Create(LocalHook.GetProcAddress("ntdll.dll", "NtQueryDirectoryObject"),new DNtQueryDirectoryObject(NtQueryDirectoryObjectHooked),this);

                LocalHook NtOpenFileHook = LocalHook.Create(LocalHook.GetProcAddress("ntdll.dll", "NtOpenFile"),new DNtOpenFile(NtOpenFileHooked),this);

                LocalHook NtCreateFileHook= LocalHook.Create(LocalHook.GetProcAddress("ntdll.dll", "NtCreateFile"),new DNtCreateFile(NtCreateFileHooked),this);

                LocalHook NtOpenDirectoryObjectHook= LocalHook.Create(LocalHook.GetProcAddress("ntdll.dll", "NtOpenDirectoryObject"),new DNtOpenDirectoryObject(NtOpenDirectoryObjectHooked),this);

                //LocalHook NtQueryDirectoryFileHook= LocalHook.Create(LocalHook.GetProcAddress("ntdll.dll", "NtQueryDirectoryFile"),new DNtQueryDirectoryFile(NtQueryDirectoryFile_hooked),this);


                CreateFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                OpenFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                ReadFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                fopenHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                _wfopen_sHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                _wfsopenHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                fopen_sHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                wsopen_sHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                //createProcessHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                readfileexHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                createfilemapHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                loadLibrarywHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                loadLibraryaHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                loadLibraryExWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                FindFirstFileWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                GetFileAttributesExWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                wfreopenHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                _waccess_sHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                _wstat64i32Hook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                //NtQueryDirectoryObjectHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                NtOpenFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                NtOpenDirectoryObjectHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                //NtQueryDirectoryFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            }
            catch (Exception ExtInfo)
            {
                Console.Error.Write("error:"+ExtInfo.ToString());
                Interface.ReportException(ExtInfo);

                return;
            }

            Interface.IsInstalled(RemoteHooking.GetCurrentProcessId());

            RemoteHooking.WakeUpProcess();

            // wait for host process termination...
            try
            {
                while (true)
                {
                    Thread.Sleep(1);

                    // transmit newly monitored file accesses...
                    if (Queue.Count > 0)
                    {
                        String[] Package = null;

                        lock (Queue)
                        {
                            Package = Queue.ToArray();

                            Queue.Clear();
                        }

                        Interface.OnCreateFile(RemoteHooking.GetCurrentProcessId(), Package);
                    }

                    if (oqueue.Count > 0)
                    {
                        String[] package = null;
                        lock (oqueue)
                        {
                            package = oqueue.ToArray();

                            oqueue.Clear();
                        }

                        Interface.OnOpenFile(RemoteHooking.GetCurrentProcessId(), package);

                    }
                    else
                        Interface.Ping();
                }
            }
            catch
            {
                // Ping() will raise an exception if host is unreachable
            }
        }
        [System.Runtime.InteropServices.StructLayout(LayoutKind.Sequential)]
        public struct OFSTRUCT
        {
            public byte cBytes;
            public byte fFixedDisc;
            public UInt16 nErrCode;
            public UInt16 Reserved1;
            public UInt16 Reserved2;
            [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szPathName;
        }
        [Flags]
        enum OpenFileStyle : uint
        {
            OF_CANCEL = 0x00000800,  // Ignored. For a dialog box with a Cancel button, use OF_PROMPT.
            OF_CREATE = 0x00001000,  // Creates a new file. If file exists, it is truncated to zero (0) length.
            OF_DELETE = 0x00000200,  // Deletes a file.
            OF_EXIST = 0x00004000,  // Opens a file and then closes it. Used to test that a file exists
            OF_PARSE = 0x00000100,  // Fills the OFSTRUCT structure, but does not do anything else.
            OF_PROMPT = 0x00002000,  // Displays a dialog box if a requested file does not exist
            OF_READ = 0x00000000,  // Opens a file for reading only.
            OF_READWRITE = 0x00000002,  // Opens a file with read/write permissions.
            OF_REOPEN = 0x00008000,  // Opens a file by using information in the reopen buffer.

            // For MS-DOS–based file systems, opens a file with compatibility mode, allows any process on a
            // specified computer to open the file any number of times.
            // Other efforts to open a file with other sharing modes fail. This flag is mapped to the
            // FILE_SHARE_READ|FILE_SHARE_WRITE flags of the CreateFile function.
            OF_SHARE_COMPAT = 0x00000000,

            // Opens a file without denying read or write access to other processes.
            // On MS-DOS-based file systems, if the file has been opened in compatibility mode
            // by any other process, the function fails.
            // This flag is mapped to the FILE_SHARE_READ|FILE_SHARE_WRITE flags of the CreateFile function.
            OF_SHARE_DENY_NONE = 0x00000040,

            // Opens a file and denies read access to other processes.
            // On MS-DOS-based file systems, if the file has been opened in compatibility mode,
            // or for read access by any other process, the function fails.
            // This flag is mapped to the FILE_SHARE_WRITE flag of the CreateFile function.
            OF_SHARE_DENY_READ = 0x00000030,

            // Opens a file and denies write access to other processes.
            // On MS-DOS-based file systems, if a file has been opened in compatibility mode,
            // or for write access by any other process, the function fails.
            // This flag is mapped to the FILE_SHARE_READ flag of the CreateFile function.
            OF_SHARE_DENY_WRITE = 0x00000020,

            // Opens a file with exclusive mode, and denies both read/write access to other processes.
            // If a file has been opened in any other mode for read/write access, even by the current process,
            // the function fails.
            OF_SHARE_EXCLUSIVE = 0x00000010,

            // Verifies that the date and time of a file are the same as when it was opened previously.
            // This is useful as an extra check for read-only files.
            OF_VERIFY = 0x00000400,

            // Opens a file for write access only.
            OF_WRITE = 0x00000001

        }
        [DllImport("kernel32.dll", BestFitMapping = false, ThrowOnUnmappableChar = true)]
        static extern IntPtr OpenFile(
        string lpFileName,
            IntPtr lpReOpenBuff,
   OpenFileStyle uStyle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate IntPtr DOpenFile(
        string lpFileName,
            IntPtr lpReOpenBuff,
   OpenFileStyle uStyle
            );


        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate IntPtr DCreateFile(
            String InFileName,
            UInt32 InDesiredAccess,
            UInt32 InShareMode,
            IntPtr InSecurityAttributes,
            UInt32 InCreationDisposition,
            UInt32 InFlagsAndAttributes,
            IntPtr InTemplateFile);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(IntPtr hFile, IntPtr lpBuffer,
          uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate bool DReadFile(IntPtr hFile, IntPtr lpBuffer,
          uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);


        static bool ReadFileHooked(IntPtr hFile, IntPtr lpBuffer,
          uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped)
        {
            return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, out lpNumberOfBytesRead, lpOverlapped);
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate bool DReadFileEx(IntPtr hFile, IntPtr lpBuffer,
  uint nNumberOfBytesToRead, [In] ref System.Threading.NativeOverlapped lpOverlapped,
  System.Threading.IOCompletionCallback lpCompletionRoutine);


        [DllImport("kernel32.dll")]
        static extern bool ReadFileEx(IntPtr hFile, IntPtr lpBuffer,
  uint nNumberOfBytesToRead, [In] ref System.Threading.NativeOverlapped lpOverlapped,
  System.Threading.IOCompletionCallback lpCompletionRoutine);

        static bool ReadFileExHooked(IntPtr hFile, IntPtr lpBuffer,
  uint nNumberOfBytesToRead, [In] ref System.Threading.NativeOverlapped lpOverlapped,
  System.Threading.IOCompletionCallback lpCompletionRoutine)
        {
            Console.Error.WriteLine("read file ");
            return ReadFileEx(hFile, lpBuffer, nNumberOfBytesToRead, ref lpOverlapped, lpCompletionRoutine);
        }


        // just use a P-Invoke implementation to get native API access from C# (this step is not necessary for C++.NET)
        [DllImport("kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true,
            CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr CreateFile(
            String InFileName,
            UInt32 InDesiredAccess,
            UInt32 InShareMode,
            IntPtr InSecurityAttributes,
            UInt32 InCreationDisposition,
            UInt32 InFlagsAndAttributes,
            IntPtr InTemplateFile);

        static IntPtr OpenFile_Hooked(string lpFileName, IntPtr lpReOpenBuff, OpenFileStyle uStyle)
        {

            Console.Error.WriteLine("OpenFile:{0}", lpFileName);
            try
            {
                Main This = (Main)HookRuntimeInfo.Callback;

                lock (This.oqueue)
                {
                    This.oqueue.Push("openfile [" + RemoteHooking.GetCurrentProcessId() + ":" +
                        RemoteHooking.GetCurrentThreadId() + "]: \"" + lpFileName + "\"");
                }
            }
            catch
            {
            }
            return OpenFile(lpFileName, lpReOpenBuff, uStyle);
        }

        // this is where we are intercepting all file accesses!
        static IntPtr CreateFile_Hooked(
            String InFileName,
            UInt32 InDesiredAccess,
            UInt32 InShareMode,
            IntPtr InSecurityAttributes,
            UInt32 InCreationDisposition,
            UInt32 InFlagsAndAttributes,
            IntPtr InTemplateFile)
        {

            Console.Error.WriteLine("CreateFileW:{0}", InFileName);
            try
            {
                Main This = (Main)HookRuntimeInfo.Callback;

                lock (This.Queue)
                {
                    This.Queue.Push("createfile [" + RemoteHooking.GetCurrentProcessId() + ":" +
                        RemoteHooking.GetCurrentThreadId() + "]: \"" + InFileName + "\"");
                }
            }
            catch
            {
            }

            // call original API...
            return CreateFile(
                InFileName,
                InDesiredAccess,
                InShareMode,
                InSecurityAttributes,
                InCreationDisposition,
                InFlagsAndAttributes,
                InTemplateFile);
        }





        [DllImport("api-ms-win-crt-stdio-l1-1-0.dll.dll", SetLastError = true)]
        public static extern IntPtr fopen(String filename, String mode);

        [DllImport("api-ms-win-crt-stdio-l1-1-0.dll.dll", SetLastError = true)]
        public static extern IntPtr _wfsopen([MarshalAs(UnmanagedType.LPWStr)]String filename, [MarshalAs(UnmanagedType.LPWStr)]String mode,int shlflag);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate IntPtr D_wfsopen(String filename, String mode,int shlflag);

        public static IntPtr _wfsopen_hooked(String filename, String mode,int shlflag)
        {
            Console.Error.WriteLine("_wfsopen:{0}", filename);
            return _wfsopen(filename, mode,shlflag);
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl,
            CharSet = CharSet.Ansi,
            SetLastError = true)]
        delegate IntPtr Dfopen(String filename, String mode);

        static IntPtr fopen_hooked(String filename, String mode)
        {
            Console.Error.WriteLine("fopen:{0}", filename);
            return fopen(filename, mode);
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate int D_wfopen_s(IntPtr pFile, string filename, string mode);

        [DllImport("api-ms-win-crt-stdio-l1-1-0.dll.dll", SetLastError = true)]
        static extern int _wfopen_s(IntPtr pFile, [MarshalAs(UnmanagedType.LPWStr)] string filename, [MarshalAs(UnmanagedType.LPWStr)]string mode);

        static int _wfopen_s_hooked(IntPtr pFile, string filename, string mode)
        {
            Console.Error.WriteLine("_wfsopen_s:{0}", filename);
            return _wfopen_s(pFile, filename, mode);
        }

        [DllImport("api-ms-win-crt-stdio-l1-1-0.dll.dll", SetLastError = true)]
        static extern int fopen_s(IntPtr pFile, [MarshalAs(UnmanagedType.LPStr)] string filename, [MarshalAs(UnmanagedType.LPStr)]string mode);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl,
            CharSet = CharSet.Ansi,
            SetLastError = true)]
        delegate int D_fopen_s(IntPtr pFile, string filename, string mode);

        static int fopen_s_hooked(IntPtr pFile, string filename, string mode)
        {
            Console.Error.WriteLine("fopen_s:{0}", filename);
            return fopen_s(pFile, filename, mode);
        }



        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(
           string lpApplicationName,
           string lpCommandLine,
           IntPtr lpProcessAttributes,
           IntPtr lpThreadAttributes,
           bool bInheritHandles,
           uint dwCreationFlags,
           IntPtr lpEnvironment,
           string lpCurrentDirectory,
           IntPtr lpStartupInfo,
           IntPtr lpProcessInformation);

        static bool CreateProcessHooked(
           string lpApplicationName,
           string lpCommandLine,
           IntPtr lpProcessAttributes,
           IntPtr lpThreadAttributes,
           bool bInheritHandles,
           uint dwCreationFlags,
           IntPtr lpEnvironment,
           string lpCurrentDirectory,
           IntPtr lpStartupInfo,
           IntPtr lpProcessInformation)
        {
            Console.Error.WriteLine("create process");
            return CreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate bool DCreateProcess(
           string lpApplicationName,
           string lpCommandLine,
           IntPtr lpProcessAttributes,
           IntPtr lpThreadAttributes,
           bool bInheritHandles,
           uint dwCreationFlags,
           IntPtr lpEnvironment,
           string lpCurrentDirectory,
           IntPtr lpStartupInfo,
           IntPtr lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFileMapping(
       IntPtr hFile,
       IntPtr lpFileMappingAttributes,
       uint flProtect,
       uint dwMaximumSizeHigh,
       uint dwMaximumSizeLow,
       string lpName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate IntPtr DCreateFileMapping(
       IntPtr hFile,
       IntPtr lpFileMappingAttributes,
       uint flProtect,
       uint dwMaximumSizeHigh,
       uint dwMaximumSizeLow,
       string lpName);


        public static IntPtr CreateFileMappingHooked(
       IntPtr hFile,
       IntPtr lpFileMappingAttributes,
       uint flProtect,
       uint dwMaximumSizeHigh,
       uint dwMaximumSizeLow,
       string lpName)
        {
            return CreateFileMapping(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
        }

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr LoadLibraryW([MarshalAs(UnmanagedType.LPWStr)]string lpFileName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate IntPtr DLoadLibraryW(string lpName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Ansi,
            SetLastError = true)]
        delegate IntPtr DLoadLibraryA(string lpName);

        static IntPtr LoadLibraryAHooked(string name)
        {
            Console.Error.WriteLine("LoadLibraryA:{0}",name);
            IntPtr ret= LoadLibraryA(name);

            HookRuntimeInfo.UpdateUnmanagedModuleList();
            return ret;
        }

        static IntPtr LoadLibraryWHooked(string name)
        {
            Console.Error.WriteLine("LoadLibraryW:{0}",name);

            IntPtr ret=LoadLibraryW(name);
            HookRuntimeInfo.UpdateUnmanagedModuleList();
            return ret;
        }


        [DllImport("kernel32.dll",CharSet = CharSet.Unicode,
            SetLastError = true,
            CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, uint dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate IntPtr DLoadLibraryExW(string lpFileName, IntPtr hReservedNull, uint dwFlags);

        static IntPtr LoadLibraryExWHooked(string lpFileName, IntPtr hReservedNull, uint dwFlags)
        {
            Console.Error.WriteLine("LoadLibraryExW:{0}",lpFileName );

            IntPtr ret=LoadLibraryEx(lpFileName,hReservedNull,dwFlags);
            HookRuntimeInfo.UpdateUnmanagedModuleList();

            return ret;
        }



        [DllImport("api-ms-win-crt-stdio-l1-1-0.dll.dll", SetLastError = true)]
        static extern int _wsopen_s(IntPtr pfh,
   [MarshalAs(UnmanagedType.LPWStr)]string filename,
   int oflag,
   int shflag,
   int pmode);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate int Dwsopen_s(IntPtr pfh, string filename, int oflag, int shflag, int pmode);




        const int _O_RDONLY = 0x0000;  // open for reading only
        const int _O_WRONLY = 0x0001;  // open for writing only
        const int _O_RDWR = 0x0002;  // open for reading and writing
        const int _O_APPEND = 0x0008; // writes done at eof

        const int _O_CREAT = 0x0100;// create and open file
        const int _O_TRUNC = 0x0200; // open and truncate
        const int _O_EXCL = 0x0400; // open only if file doesn't already exist

        // O_TEXT files have <cr><lf> sequences translated to <lf> on read()'s and <lf>
        // sequences translated to <cr><lf> on write()'s

        const int _O_TEXT = 0x4000; // file mode is text (translated)
        const int _O_BINARY = 0x8000; // file mode is binary (untranslated)
        const int _O_WTEXT = 0x10000; // file mode is UTF16 (translated)
        const int _O_U16TEXT = 0x20000; // file mode is UTF16 no BOM (translated)
        const int _O_U8TEXT = 0x40000; // file mode is UTF8  no BOM (translated)

        // macro to translate the C 2.0 name used to force binary mode for files
        const int _O_RAW = _O_BINARY;

        const int _O_NOINHERIT = 0x0080;// child process doesn't inherit file
        const int _O_TEMPORARY = 0x0040; // temporary file bit (file is deleted when last handle is closed)
        const int _O_SHORT_LIVED = 0x1000; // temporary storage file, try not to flush
        const int _O_OBTAIN_DIR = 0x2000;// get information about a directory
        const int _O_SEQUENTIAL = 0x0020;// file access is primarily sequential
        const int _O_RANDOM = 0x0010;// file access is primarily random

        static int[] OFLAGS = {_O_RDONLY, _O_WRONLY,_O_RDWR,_O_APPEND,_O_CREAT,_O_TRUNC,_O_EXCL,_O_TEXT,_O_BINARY,_O_WTEXT,
            _O_U16TEXT,_O_U8TEXT,_O_NOINHERIT,_O_TEMPORARY,_O_SHORT_LIVED,_O_OBTAIN_DIR,_O_SEQUENTIAL,_O_RANDOM};

        static string[] OFLAGS_STR = {"RDONLY", "WRONLY","RDWR","APPEND","CREAT","TRUNC","EXCL","TEXT","BINARY","WTEXT",
            "U16TEXT","U8TEXT","NOINHERIT","TEMPORARY","SHORT_LIVED","OBTAIN_DIR","SEQUENTIAL","RANDOM"};
        static int wsopen_sHooked(IntPtr pfh,
   string filename,
   int oflag,
   int shflag,
   int pmode)
        {

            string flags = "";
            for(int i=0;i<OFLAGS.Length;++i)
            {
                if ((oflag & OFLAGS[i]) !=0)
                {
                    flags +=("|" +OFLAGS_STR[i]);
                }

            }

            Console.Error.WriteLine("wsopen_s:{0},{1}",flags,filename);
            return _wsopen_s(pfh,filename,oflag,shflag,pmode);
        }
        public const int MAX_PATH = 260;
        public const int MAX_ALTERNATE = 14;

        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        };


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WIN32_FIND_DATA
        {
            public uint dwFileAttributes;
            public FILETIME ftCreationTime;
            public FILETIME ftLastAccessTime;
            public FILETIME ftLastWriteTime;
            public uint nFileSizeHigh; //changed all to uint, otherwise you run into unexpected overflow
            public uint nFileSizeLow;  //|
            public uint dwReserved0;   //|
            public uint dwReserved1;   //v
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_ALTERNATE)]
            public string cAlternate;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr FindFirstFileW(string lpFileName, out WIN32_FIND_DATA lpFindFileData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate IntPtr DFindFirstFileW(string lpFileName, out WIN32_FIND_DATA lpFindFileData);

        static IntPtr FindFirstFileWHooked(string lpFileName, out WIN32_FIND_DATA lpFindFileData)
        {

            Console.Error.WriteLine("FindFirstFileW:{0}",lpFileName);

            return FindFirstFileWHooked(lpFileName, out lpFindFileData);
        }

        public enum GET_FILEEX_INFO_LEVELS
        {
            GetFileExInfoStandard,
            GetFileExMaxInfoLevel
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetFileAttributesEx(string lpFileName,GET_FILEEX_INFO_LEVELS fInfoLevelId, IntPtr lpFileInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate bool DGetFileAttributesExW(string lpFileName,GET_FILEEX_INFO_LEVELS fInfoLevelId, IntPtr lpFileInformation);



        static bool GetFileAttributesExWHooked(string lpFileName,GET_FILEEX_INFO_LEVELS fInfoLevelId, IntPtr lpFileInformation)
        {
            Console.Error.WriteLine("GetFileAttributesEx:{0}",lpFileName);
            return GetFileAttributesEx(lpFileName, fInfoLevelId, lpFileInformation);
        }

        [DllImport("api-ms-win-crt-stdio-l1-1-0.dll",CharSet=CharSet.Unicode)]
        static extern bool _wfreopen_s(IntPtr pFile, string path, string mode, IntPtr stream);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate bool D_wfreopen_s(IntPtr pFile, string path, string mode, IntPtr stream);

        static bool _wfreopen_sHooked(IntPtr pFile, string path, string mode, IntPtr stream)
        {
            Console.Error.WriteLine("_wfreopen_s:{0}",pFile);
            return _wfreopen_s(pFile, path, mode, stream);
        }

        [DllImport("api-ms-win-crt-filesystem-l1-1-0.dll")]
        static extern int _waccess_s([MarshalAs(UnmanagedType.LPWStr)]string path,   int mode);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate int D_waccess_s([MarshalAs(UnmanagedType.LPWStr)]string path,   int mode);

        static int _waccess_sHooked([MarshalAs(UnmanagedType.LPWStr)]string path,   int mode)
        {
            Console.Error.WriteLine("_waccess_s:{0}",path);

            return _waccess_s(path, mode);
        }

        [DllImport("api-ms-win-crt-filesystem-l1-1-0.dll")]
        static extern int _wstat64i32(  [MarshalAs(UnmanagedType.LPWStr)] string path,   IntPtr buffer);  

        [UnmanagedFunctionPointer(CallingConvention.Cdecl,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate int D_wstat64i32(  [MarshalAs(UnmanagedType.LPWStr)] string path,   IntPtr buffer);  

        static int _wstat64i32Hooked(  string path,   IntPtr buffer)
        {
            Console.Error.WriteLine("_wstat64i32:{0}",path);

            return _wstat64i32(path, buffer);
        }


        [DllImport("ntdll.dll")]
        public static extern int NtQueryDirectoryObject(
  IntPtr DirectoryHandle,
  IntPtr Buffer,
  int Length,
  bool ReturnSingleEntry,
  bool RestartScan,
  ref uint Context,
  out uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate int DNtQueryDirectoryObject(
  IntPtr DirectoryHandle,
  IntPtr Buffer,
  int Length,
  bool ReturnSingleEntry,
  bool RestartScan,
  ref uint Context,
  out uint ReturnLength);


        public static int NtQueryDirectoryObjectHooked(
  IntPtr DirectoryHandle,
  IntPtr Buffer,
  int Length,
  bool ReturnSingleEntry,
  bool RestartScan,
  ref uint Context,
  out uint ReturnLength)
        {

            Console.Error.WriteLine("NtQueryDirectoryObject hooked");
            return NtQueryDirectoryObject(
  DirectoryHandle,
  Buffer,
  Length,
  ReturnSingleEntry,
  RestartScan,
  ref Context,
  out ReturnLength);
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate int DNtOpenFile(IntPtr FileHandle,
  int DesiredAccess,
  ref  OBJECT_ATTRIBUTES ObjectAttributes,
  IntPtr IoStatusBlock,
  ulong ShareAccess,
  ulong OpenOptions);


        [DllImport("ntdll.dll")]
        static extern int NtOpenFile(
  IntPtr FileHandle,
  int DesiredAccess,
  ref OBJECT_ATTRIBUTES ObjectAttributes,
  IntPtr IoStatusBlock,
  ulong ShareAccess,
  ulong OpenOptions
);

        [StructLayout(LayoutKind.Sequential, Pack = 0,CharSet = CharSet.Unicode)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
        public struct OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern uint GetFinalPathNameByHandle(IntPtr hFile, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        static int NtOpenFileHooked(
  IntPtr FileHandle,
  int DesiredAccess,
  ref OBJECT_ATTRIBUTES ObjectAttributes,
  IntPtr IoStatusBlock,
  ulong ShareAccess,
  ulong OpenOptions
)
        {

            UNICODE_STRING str = (UNICODE_STRING)Marshal.PtrToStructure(ObjectAttributes.ObjectName, typeof(UNICODE_STRING));

            var st=Marshal.PtrToStringUni(str.Buffer);

            int ret=NtOpenFile(FileHandle, DesiredAccess, ref ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);

            Console.Error.WriteLine("NtOpenFile:{0},{1}", st,FileHandle);
            return ret;
            //            StringBuilder sb=new StringBuilder(200);

            //       GetFinalPathNameByHandle(FileHandle, sb, (uint)sb.Capacity, 0);

            //          Console.Error.WriteLine("NtOpenFile:{0}",sb);


            //         return ret;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate int DNtCreateFile(
                IntPtr handle,
                System.IO.FileAccess access,
                ref OBJECT_ATTRIBUTES objectAttributes,
                IntPtr ioStatus,
                ref long allocSize,
                uint fileAttributes,
                System.IO.FileShare share,
                uint createDisposition,
                uint createOptions,
                IntPtr eaBuffer,
                uint eaLength);
        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = true)]
        public static extern int NtCreateFile(
                IntPtr handle,
                System.IO.FileAccess access,
                ref OBJECT_ATTRIBUTES objectAttributes,
                IntPtr ioStatus,
                ref long allocSize,
                uint fileAttributes,
                System.IO.FileShare share,
                uint createDisposition,
                uint createOptions,
                IntPtr eaBuffer,
                uint eaLength);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = true)]
        static extern int NtQueryDirectoryFile(IntPtr FileHandle, IntPtr Event, 
            IntPtr ApcRoutine, IntPtr ApcContext, IntPtr   IoStatusBlock, IntPtr FileInformation, ulong Length, 
            int FileInformationClass, bool ReturnSingleEntry, IntPtr FileName, bool RestartScan );

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate int DNtQueryDirectoryFile(IntPtr FileHandle, IntPtr Event, 
            IntPtr ApcRoutine, IntPtr ApcContext, IntPtr   IoStatusBlock, IntPtr FileInformation, ulong Length, 
            int FileInformationClass, bool ReturnSingleEntry, IntPtr FileName, bool RestartScan );

        static int NtQueryDirectoryFile_hooked(IntPtr FileHandle, IntPtr Event, 
            IntPtr ApcRoutine, IntPtr ApcContext, IntPtr   IoStatusBlock, IntPtr FileInformation, ulong Length, 
            int FileInformationClass, bool ReturnSingleEntry, IntPtr FileName, bool RestartScan)
        {


            Console.Error.Write("{0},NtQueryDirectoryFile:{1}",Thread.CurrentThread.ManagedThreadId,FileHandle);
            if (FileName != IntPtr.Zero)
            {
                UNICODE_STRING str = (UNICODE_STRING)Marshal.PtrToStructure(FileName, typeof(UNICODE_STRING));

                var st = Marshal.PtrToStringUni(str.Buffer);

                Console.Error.WriteLine(st);

            }
                Console.Error.WriteLine();

            return NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length,
                FileInformationClass, ReturnSingleEntry, FileName,RestartScan);

        }





        public static int NtCreateFileHooked(
                IntPtr handle,
                System.IO.FileAccess access,
                ref OBJECT_ATTRIBUTES objectAttributes,
                IntPtr ioStatus,
                ref long allocSize,
                uint fileAttributes,
                System.IO.FileShare share,
                uint createDisposition,
                uint createOptions,
                IntPtr eaBuffer,
                uint eaLength)
        {
            UNICODE_STRING str = (UNICODE_STRING)Marshal.PtrToStructure(objectAttributes.ObjectName, typeof(UNICODE_STRING));

            var st=Marshal.PtrToStringUni(str.Buffer);


            Console.Error.WriteLine("NtCreateFile:{0}",st);
            return NtCreateFile(handle, access, ref objectAttributes, ioStatus, ref allocSize, fileAttributes,
                share, createDisposition, createOptions, eaBuffer, eaLength);
        }

        [DllImport("ntdll.dll")]
        public static extern int NtOpenDirectoryObject(
  out IntPtr DirectoryHandle,
  uint DesiredAccess,
  ref OBJECT_ATTRIBUTES ObjectAttributes);
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
delegate int DNtOpenDirectoryObject(
  out IntPtr DirectoryHandle,
  uint DesiredAccess,
  ref OBJECT_ATTRIBUTES ObjectAttributes);

        public static int NtOpenDirectoryObjectHooked(
  out IntPtr DirectoryHandle,
  uint DesiredAccess,
  ref OBJECT_ATTRIBUTES ObjectAttributes)
        {
            Console.Error.WriteLine("open directory object hook");

            return NtOpenDirectoryObject(out DirectoryHandle,DesiredAccess,ref ObjectAttributes);
        }




    }

}
