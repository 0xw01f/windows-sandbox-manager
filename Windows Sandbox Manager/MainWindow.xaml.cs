using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using Microsoft.Win32;
using System.Diagnostics;
using System.Security.Principal;
using System.Threading.Tasks;



namespace Sandbox_Activator
{
    public partial class MainWindow : Window
    {
        // Constants for window dragging
        private const int WM_NCLBUTTONDOWN = 0x00A1;
        private const int HT_CAPTION = 0x0002;

        // Import the necessary Windows API functions
        [DllImport("user32.dll")]
        private static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
        [DllImport("user32.dll")]
        private static extern bool ReleaseCapture();

        public MainWindow()
        {
            InitializeComponent();
            this.WindowStartupLocation = WindowStartupLocation.CenterScreen;

        }

        void startSpinner()
        {
            loadingSpinner.Visibility = Visibility.Visible;
            contentGrid.Opacity = 0.3;
            contentGrid.IsEnabled = false;
        }
        void stopSpinner()
        {
            loadingSpinner.Visibility = Visibility.Collapsed;
            contentGrid.Opacity = 1;
            contentGrid.IsEnabled = true;

        }


        private void CheckSystemInformation()
        {
            try
            {
                bool isVirtualizationEnabled = CheckVirtualizationEnabled();
                bool isWindows10ProOrEnterprise = IsWindows10ProOrEnterprise();
                bool isWindows11 = IsWindows11();

                string message = "";
                bool isCompatible = false;

                if (isVirtualizationEnabled)
                {
                    message += "La virtualisation est activée.\n";
                    isCompatible = true;
                }
                else
                {
                    message += "La virtualisation n'est pas activée.\n";
                    isCompatible = false;
                }

                if (isWindows10ProOrEnterprise)
                {
                    message += "L'ordinateur utilise Windows 10 Professionnel ou Enterprise avec une version de build supérieure à 18305.\n";
                    isCompatible = true;
                }
                else if (isWindows11)
                {
                    message += "L'ordinateur utilise Windows 11.\n";
                    isCompatible = true;
                }
                else
                {
                    isCompatible = false;
                }

                if (isCompatible == false)
                {
                    message = "L'ordinateur ne répond pas aux critères spécifiés.";
                }



                MessageBox.Show(message);
            }
            catch (Exception exception)
            {
                MessageBox.Show("Error while checking the system information :\n" + exception);
            }
        }

        private bool CheckVirtualizationEnabled()
        {

            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard"))
            {
                int enabled = Convert.ToInt32(key.GetValue("EnableVirtualizationBasedSecurity"));

                // Vérifier si la virtualisation est activée
                return (enabled == 1);
            }
        }

        private bool IsWindows10ProOrEnterprise()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
            {
                string productName = key.GetValue("ProductName") as string;
                string editionId = key.GetValue("EditionID") as string;
                int buildNumber = Convert.ToInt32(key.GetValue("CurrentBuildNumber"));

                // Vérifier si l'ordinateur utilise Windows 10 Professionnel ou Enterprise avec une version de build supérieure à 18305
                return (productName.Contains("Windows 10") && (editionId.Contains("Professional") || editionId.Contains("Enterprise"))) && buildNumber > 18305;
            }
        }

        private bool IsWindows11()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
            {
                string productName = key.GetValue("ProductName") as string;
                int buildNumber = Convert.ToInt32(key.GetValue("CurrentBuildNumber"));

                // Vérifier si l'ordinateur utilise Windows 11
                return productName.Contains("Windows 11") && buildNumber > 0;
            }
        }


        void ActivateHardwareVirtualization()
        {

            try { 
                // Run PowerShell command to enable hardware virtualization
                string command = "Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\" -Name \"EnableVirtualizationBasedSecurity\" -Value 1";

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "powershell.exe";
                psi.Arguments = $"-Command \"{command}\"";
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;

                using (Process process = new Process())
                {
                    process.StartInfo = psi;
                    process.Start();

                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                }
            }
            catch (Exception exception)
            {
                MessageBox.Show("Error while activating the hardware virtualization :\n" + exception);
            }
        }

        void ActivateWindowsSandbox()
        {


            try { 
           

                if (IsRunAsAdministrator())
                {

                    string command = "Enable-WindowsOptionalFeature -FeatureName \"Containers-DisposableClientVM\" -Online -NoRestart";
                    int exitCode = RunElevatedPowerShellCommand(command);
                    if (exitCode == 0)
                    {
                        MessageBox.Show("Windows Sandbox à été désactivée avec succès. L'ordinateur va redémarrer une fois cette fenêtre fermée.");
                        RestartComputer();
                    }
                    else
                    {
                        MessageBox.Show("Erreur: La désactivation de la Sandbox a échouée.");
                    }
                }
                else
                {
                    MessageBox.Show("Veuillez lancer l'application en tant qu'administrateur.");
                }
                Application.Current.Dispatcher.Invoke(() =>
                {
                    stopSpinner();
                });

            }
            catch (Exception exception)
            {
                MessageBox.Show("Error while activating the windows sandbox :\n" + exception);
            }
        }

        void DeactivateWindowsSandbox()
        {

            try { 
                Application.Current.Dispatcher.Invoke(() =>
                {
                    startSpinner();
                });
                if (IsRunAsAdministrator())
                {
                
                    string command = "Disable-WindowsOptionalFeature -FeatureName \"Containers-DisposableClientVM\" -Online -NoRestart";
                    int exitCode = RunElevatedPowerShellCommand(command);
                    if (exitCode == 0)
                    {
                        MessageBox.Show("Windows Sandbox à été désactivée avec succès. L'ordinateur va redémarrer une fois cette fenêtre fermée.");
                        RestartComputer();
                    }
                    else
                    {
                        MessageBox.Show("Erreur: La désactivation de la Sandbox a échouée.");
                    }
                }
                else
                {
                    MessageBox.Show("Veuillez lancer l'application en tant qu'administrateur.");
                }
                Application.Current.Dispatcher.Invoke(() =>
                {
                    stopSpinner();
                });
            }
            catch (Exception exception)
            {
                MessageBox.Show("Error while deactivating the windows sandbox :\n" + exception);
            }
        }

        static int RunElevatedPowerShellCommand(string command)
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "powershell.exe";
            psi.Arguments = $"-Command \"{command}\"";
            psi.Verb = "runas"; // Run as administrator
            psi.CreateNoWindow = true;
            psi.WindowStyle = ProcessWindowStyle.Hidden;



            using (Process process = new Process())
            {
                process.StartInfo = psi;
                process.Start();
                process.WaitForExit();
                return process.ExitCode;
            }
        }

        static bool IsRunAsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        static void RestartComputer()
        {
            Process.Start("shutdown", "/r /t 5");

           
        }

        private async void ActivateButton_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                startSpinner();
            });
            ActivateHardwareVirtualization();
            await Task.Run(() => CheckSystemInformation());

            await Task.Run(() => ActivateWindowsSandbox());
            
        }

        private async void DeactivateButton_Click(object sender, RoutedEventArgs e)
        {
            await Task.Run(() => DeactivateWindowsSandbox());
            
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            // Enable window dragging by handling the mouse left button down event on the title bar
            WindowInteropHelper helper = new WindowInteropHelper(this);
            HwndSource.FromHwnd(helper.Handle)?.AddHook(WndProc);
        }

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (msg == WM_NCLBUTTONDOWN && wParam.ToInt32() == HT_CAPTION)
            {
                // Handle left button down event on the title bar to initiate window dragging
                ReleaseCapture();
                SendMessage(hwnd, WM_NCLBUTTONDOWN, HT_CAPTION, 0);
                handled = true;
            }
            return IntPtr.Zero;
        }

        private void Grid_MouseDown(object sender, MouseButtonEventArgs e)
        {
            try { if (e.ChangedButton == MouseButton.Left) { this.DragMove(); } } catch { }


        }

        private void TextBlock_MouseDown(object sender, MouseButtonEventArgs e)
        {
            try { if (e.ChangedButton == MouseButton.Left) { this.DragMove(); } } catch { }

        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {

            string url = "https://www.w01f.fr";
            Process.Start(url);
        }

      
    }
}
