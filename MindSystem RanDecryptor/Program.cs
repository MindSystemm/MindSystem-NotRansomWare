using System;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Text;

namespace MindSystem_RanDecryptor
{
    public class Utils
    {

        public static bool Decryptor(string file, Byte[] key)
        {

            try
            {
                string fileDir = new FileInfo(file).DirectoryName + @"\";
                string extName = new FileInfo(file).Extension;
                string fileName = new FileInfo(file).Name.Split('.')[0];
                if (extName != ".mind") return false;

                Byte[] fileData = File.ReadAllBytes(file);
                fileData = AES.decrypt(fileData, key);
                Byte[] fileOrgExtName = new byte[256];
                Array.ConstrainedCopy(fileData, fileData.Length - 256, fileOrgExtName, 0, 256);
                string fullName = Encoding.UTF8.GetString(fileOrgExtName);
                fullName = fullName.TrimEnd('\x00');
                Array.Resize(ref fileData, fileData.Length - 256);
                File.WriteAllBytes(fileDir + fullName, fileData);
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
        public static Byte[] decrypt(byte[] byte_ciphertext, Byte[] key)
        {
            RijndaelManaged provider_AES = new RijndaelManaged();
            provider_AES.KeySize = 128;
            ICryptoTransform decrypt_AES = provider_AES.CreateDecryptor(key, key);
            byte[] byte_secretContent = decrypt_AES.TransformFinalBlock(byte_ciphertext, 0, byte_ciphertext.Length);
            return byte_secretContent;
        }
    }
    static class Program
    {
        private static void decryptAll(string dir, Byte[] aesKey)
        {
            var di = new DirectoryInfo(dir);
            try
            {
                foreach (FileInfo fi in di.GetFiles("*.*"))
                    Utils.Decryptor(fi.FullName, aesKey);
                foreach (DirectoryInfo d in di.GetDirectories())
                    decryptAll(d.FullName, aesKey);
            }
            catch (Exception)
            {
            }
        }
        private static void StartExplorer()
        {
            System.Diagnostics.Process.Start("explorer.exe");
        }
        public static void ToggleTaskManager()
        {
            try
            {
                RegistryKey objRegistryKey = Registry.CurrentUser.CreateSubKey(
               @"Software\Microsoft\Windows\CurrentVersion\Policies\System");
                if (objRegistryKey.GetValue("DisableTaskMgr") == null)
                    objRegistryKey.SetValue("DisableTaskMgr", "0");
                else
                    objRegistryKey.DeleteValue("DisableTaskMgr");
                objRegistryKey.Close();
            }
            catch
            {

            }
        }
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
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
        [DllImport("user32", EntryPoint = "SetWindowsHookExA", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        public static extern int SetWindowsHookEx(int idHook, LowLevelKeyboardProcDelegate lpfn, int hMod, int dwThreadId);
        [DllImport("user32", EntryPoint = "UnhookWindowsHookEx", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        public static extern int UnhookWindowsHookEx(int hHook);
        public delegate int LowLevelKeyboardProcDelegate(int nCode, int wParam, ref KBDLLHOOKSTRUCT lParam);
        [DllImport("user32", EntryPoint = "CallNextHookEx", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        public static extern int CallNextHookEx(int hHook, int nCode, int wParam, ref KBDLLHOOKSTRUCT lParam);
        public const int WH_KEYBOARD_LL = 13;
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
        [DllImport("user32.dll")]
        private static extern int ShowWindow(int hwnd, int command);

        private const int SW_HIDE = 0;
        private const int SW_SHOW = 1;
        public struct KBDLLHOOKSTRUCT
        {
            public int vkCode;
            public int scanCode;
            public int flags;
            public int time;
            public int dwExtraInfo;
        }
        [STAThread]
        static void Main(string[] arg)
        {
            Byte[] myKey = File.ReadAllBytes(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"\key.txt");
            decryptAll(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), myKey);
            ToggleTaskManager();
            StartExplorer();
            IntPtr hWnd = FindWindow("Progman", "Program Manager");
            ToggleDesktopIcons();
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableLockWorkstation", "0", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableChangePassword", "0", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "NoClose", "0", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "NoLogoff", "0", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System", "HideFastUserSwitching", "0", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "1", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools", "0", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", "0", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System", "DisableCMD", "0", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System", "NoClose", "0", Microsoft.Win32.RegistryValueKind.DWord);
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoClose", "0", Microsoft.Win32.RegistryValueKind.DWord);
            int intLLKey = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, System.Runtime.InteropServices.Marshal.GetHINSTANCE(System.Reflection.Assembly.GetExecutingAssembly().GetModules()[0]).ToInt32(), 0);
            UnhookWindowsHookEx(intLLKey);
            File.Delete(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"\key.txt");
            MessageBox.Show("Nice, your computer has been unlocked ! ", "Sucess", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
