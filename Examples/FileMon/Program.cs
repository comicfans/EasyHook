using System;
using System.Collections.Generic;
using System.Runtime.Remoting;
using System.Text;
using System.IO;
using EasyHook;
using System.Windows.Forms;

namespace FileMon
{
    public class FileMonInterface : MarshalByRefObject
    {
        public void IsInstalled(Int32 InClientPID)
        {
            Console.WriteLine("FileMon has been installed in target {0}.\r\n", InClientPID);
        }

        public void OnCreateFile(Int32 InClientPID, String[] InFileNames)
        {
            for (int i = 0; i < InFileNames.Length; i++)
            {
                //Console.WriteLine("create file {0}",InFileNames[i]);
            }
        }

        public void OnOpenFile(Int32 InClientPID, String[] filenames)
        {

            foreach(var s in filenames)
            {
                //Console.WriteLine("open file {0}", s);

            }

        }

        public void ReportException(Exception InInfo)
        {
            Console.WriteLine("The target process has reported an error:\r\n" + InInfo.ToString());
        }

        public void Ping()
        {
        }
    }

    class Program
    {
        static String ChannelName = null;

        static void Main(string[] args)
        {

            string targetExe = @"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe";
            string tar1=@"D:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\amd64\cl.exe";

            int TargetPID;
            

            try
            {
                RemoteHooking.IpcCreateServer<FileMonInterface>(ref ChannelName, WellKnownObjectMode.SingleCall);

                string injectionLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "FileMonInject.dll");

                var arg = @" -E vs_link_exe --intdir=CMakeFiles\main.dir --manifests  -- C:\PROGRA~2\MICROS~3\2017\COMMUN~1\VC\Tools\MSVC\1410~1.247\bin\HostX86\x86\link.exe /nologo CMakeFiles\main.dir\main.cpp.obj  /out:main.exe /implib:main.lib /pdb:main.pdb /version:0.0  /machine:X86 /debug /INCREMENTAL /subsystem:console  kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib";

                var arg1=@"  /nologo /TP   /DWIN32 /D_WINDOWS /W3 /GR /EHsc /D_DEBUG /MDd /Zi /Ob0 /Od /RTC1  /FoI:\test_proj\build\CMakeFiles\main.dir\main.cpp.obj /FdI:\test_proj\build\CMakeFiles\main.dir\ /FS -c I:\test_proj\main.cpp /I G: /I H:";
                RemoteHooking.CreateAndInject(tar1, arg1 , 0, InjectionOptions.DoNotRequireStrongName, injectionLibrary, injectionLibrary, out TargetPID, ChannelName);
                Console.WriteLine("Created and injected process {0}", TargetPID);
                Console.WriteLine("<Press any key to exit>");
                Console.ReadKey();
            }
            catch (Exception ExtInfo)
            {
                Console.WriteLine("There was an error while connecting to target:\r\n{0}", ExtInfo.ToString());
                Console.WriteLine("<Press any key to exit>");
                Console.ReadKey();
            }
        }
    }
}