using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;
using System.Windows;
using System.Management;
using System.Net.NetworkInformation;
using System.Linq;
using System.Net;
using System.Windows.Documents;
using System.Text.RegularExpressions;
using System.Windows.Media;

namespace UNBURST
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        /// <summary>
        /// Used to determine if SUNBURST FQDNs have already been decoded, and sets buttons isEnabled state accordingly.
        /// </summary>
        public bool Calculated
        {
            get
            {
                return calculated;
            }
            set
            {
                calculated = value;
                if (!value)
                {
                    ButtonCalcGUIDs.IsEnabled = true;
                }
                else
                {
                    ButtonCalcGUIDs.IsEnabled = false;
                }
            }
        }
        private bool calculated = false;

        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Generates the User ID that SUNBURST uses to identify hosts
        /// </summary>
        private string getSUNBURSTGUID(string id)
        {
            byte[] hash64;
            hash64 = new byte[8];
            Array.Clear(hash64, 0, hash64.Length);
            using (MD5 md = MD5.Create())
            {
                byte[] bytes = Encoding.ASCII.GetBytes(id);
                byte[] array = md.ComputeHash(bytes);
                for (int i = 0; i < array.Length; i++)
                {
                    byte[] array2 = hash64;
                    int num = i % hash64.Length;
                    array2[num] ^= array[i];
                }
            }
            return BitConverter.ToString(hash64).Replace("-", "");
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            if (null != properties.DomainName)
                Textbox_Domain.Text = properties.DomainName;
        }

        /// <summary>
        /// For searching RichTextBox
        /// </summary>
        public static IEnumerable<TextRange> GetAllWordRanges(FlowDocument document)
        {
            string pattern = @"[^\W](\w|[-']{1,2}(.?=\w))*";
            TextPointer pointer = document.ContentStart;
            while (pointer != null)
            {
                if (pointer.GetPointerContext(LogicalDirection.Forward) == TextPointerContext.Text)
                {
                    string textRun = pointer.GetTextInRun(LogicalDirection.Forward);
                    MatchCollection matches = Regex.Matches(textRun, pattern);
                    foreach (Match match in matches)
                    {
                        int startIndex = match.Index;
                        int length = match.Length;
                        TextPointer start = pointer.GetPositionAtOffset(startIndex);
                        TextPointer end = start.GetPositionAtOffset(length);
                        yield return new TextRange(start, end);
                    }
                }

                pointer = pointer.GetNextContextPosition(LogicalDirection.Forward);
            }
        }

        /// <summary>
        /// Work in progress, I want to make this async so I can disable it during remote connections
        /// </summary>
        private /*async*/ void Button_Remote_Click(object sender, RoutedEventArgs e)
        {
            Button_Remote.Content = "Please wait...";
            Button_Remote.IsEnabled = false;
            Textbox_SBID.Text = "";
            Textbox_GUID.Text = "";
            TextRange textRange = new TextRange(
                // TextPointer to the start of content in the RichTextBox.
                RichTextboxFQDNs.Document.ContentStart,
                // TextPointer to the end of content in the RichTextBox.
                RichTextboxFQDNs.Document.ContentEnd
            );
            textRange.ApplyPropertyValue(TextElement.BackgroundProperty, Brushes.White);
            textRange.ApplyPropertyValue(TextElement.ForegroundProperty, Brushes.Black);

            if (!calculated)
                calculateGUIDs();

            infos info = new infos()
            {
                RemoteIP = TextBox_IP.Text.Trim(),
                Domain = Textbox_Domain.Text.Trim()
            };

            //Declare a new BackgroundWorker
            //        BackgroundWorker worker = new BackgroundWorker();
            //        worker.DoWork += (o, ea) =>
            //        {
            //            try
            //            {
            //                // Call your device

            //                // If ou need to interact with the main thread
            //                Button_Remote.Dispatcher.Invoke(new Action(() => connectAndRetreiveInfo(info)));
            //}
            //            catch (Exception exp)
            //            {
            //            }
            //        };

            //This event is raise on DoWork complete
            //worker.RunWorkerCompleted += (o, ea) =>
            //{
            //    //Work to do after the long process
            //    disableGui = false;
            //};

            connectAndRetreiveInfo(ref info);
            //await Task.Run(() => connectAndRetreiveInfo(info));
            //worker.RunWorkerAsync();


        }

        /// <summary>
        /// Data shuttled to and from the connectAndRetreiveInfo method
        /// </summary>
        private class infos
        {
            /// <summary>
            /// IP or hostname of system to connect to generate GUID
            /// </summary>
            public string RemoteIP { get; set; }
            /// <summary>
            /// Domain used to generate GUID
            /// </summary>
            public string Domain { get; set; }
            /// <summary>
            /// Future use, I want to shuttle data back with this
            /// </summary>
            public string FQDNs { get; set; }
        }

        /// <summary>
        /// Connect to remote host and retrieve required to generate GUID
        /// </summary>
        private void connectAndRetreiveInfo(ref infos info)
        {
            string domain = info.Domain;
            string machineGuid = string.Empty;
            string remoteIP = info.RemoteIP.Trim();
            string id = string.Empty;

            if (!ValidateIPv4(remoteIP))
            {
                var hostEntry = Dns.GetHostEntry(remoteIP);
                if (hostEntry.AddressList.Length > 0)
                {
                    var resolvedIP = hostEntry.AddressList[0];
                    if (null != resolvedIP)
                        remoteIP = resolvedIP.ToString();
                }

                if (!ValidateIPv4(remoteIP))
                {
                    restoreButton("Invalid address.");
                    return;
                }
            }

            //Needed permissions to get remote registry
            PermissionSet permissions = _UnsafeGetAssertPermSet();
            permissions.Demand();

            //Recommended options for WMIC
            ConnectionOptions options = new ConnectionOptions
            {
                Impersonation = ImpersonationLevel.Impersonate
            };

            //Get Machines MAC addresses
            List<string> MACs = new List<string>();
            try
            {
                ManagementScope scope = new ManagementScope($"\\\\{remoteIP}\\root\\cimv2", options);
                scope.Connect();
                ObjectQuery query = new ObjectQuery("SELECT MACAddress FROM Win32_NetworkAdapter where PhysicalAdapter='true'");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                var wmiResult = searcher.Get();
                foreach (ManagementObject m in wmiResult)
                    if (m["MACAddress"] != null)
                        MACs.Add(m["MACAddress"].ToString().Replace(":", ""));
            }
            catch
            {
                restoreButton("Could not retreive remote hosts MAC address, check WMIC connectivity.");
                return;
            }

            //Remove duplicates
            MACs = MACs.Distinct().ToList();

            //Get MachineGuid
            try
            {
                RegistryKey environmentKey = RegistryKey.OpenRemoteBaseKey(
                                   RegistryHive.LocalMachine, remoteIP, RegistryView.Registry64).OpenSubKey("SOFTWARE\\Microsoft\\Cryptography",
                                   RegistryKeyPermissionCheck.ReadSubTree, System.Security.AccessControl.RegistryRights.QueryValues);
                if (environmentKey != null)
                {
                    var guid = environmentKey.GetValue("MachineGuid");
                    if (guid != null)
                        machineGuid = guid.ToString();
                }
            }
            catch
            {
                restoreButton("Could not retreive remote hosts MachineGuid. Check remote registry connectivity.");
                return;
            }

            if (MACs.Count > 0 && domain != "" && machineGuid != "")
            {
                string sbidsText = string.Empty;
                string guidsText = string.Empty;
                int targetMAC = 0;
                for (int i = 0; i < MACs.Count; i++)
                {
                    id = MACs[i] + domain + machineGuid;
                    string sbguid = getSUNBURSTGUID(id);

                    IEnumerable<TextRange> wordRanges = GetAllWordRanges(RichTextboxFQDNs.Document);
                    bool firstWord = true;
                    recurs = true;
                    foreach (TextRange wordRange in wordRanges)
                    {
                        if (wordRange.Text == sbguid)
                        {
                            targetMAC = i;
                            wordRange.ApplyPropertyValue(TextElement.BackgroundProperty, Brushes.Yellow);
                            wordRange.ApplyPropertyValue(TextElement.ForegroundProperty, Brushes.Crimson);
                            if (firstWord)
                            {
                                firstWord = false;
                                Rect r = wordRange.Start.GetCharacterRect(LogicalDirection.Backward);
                                RichTextboxFQDNs.ScrollToVerticalOffset(r.Y);
                            }

                        }
                    }
                    recurs = false;
                    if (targetMAC == i)
                    {
                        sbidsText = id + "\r\n" + sbidsText;
                        guidsText = sbguid + "\r\n" + guidsText;
                    }
                    else
                    {
                        sbidsText += id + "\r\n";
                        guidsText += sbguid + "\r\n";
                    }
                }

                Textbox_SBID.Text = sbidsText.TrimEnd();
                Textbox_GUID.Text = guidsText.TrimEnd();
                restoreButton();
            }
            else
            {
                if (MACs.Count == 0)
                    restoreButton("Could not retreive remote hosts MAC address, check WMIC connectivity.");
                if (machineGuid == "")
                    restoreButton("Could not retreive remote hosts MachineGuid. Check remote registry connectivity.");
                if (domain == "")
                    restoreButton("Please enter a valid domain name.");
            }
        }

        /// <summary>
        /// Restores the buttons IsEnabled state. Work in progress, needs async OnCompleted event
        /// </summary>
        private void restoreButton(string guidtext = "")
        {
            Button_Remote.IsEnabled = true;
            Button_Remote.Content = "Get value from remote machine";
            if (guidtext != "")
                Textbox_SBID.Text = guidtext;
        }

        /// <summary>
        /// Permissions required to connect to remote registry
        /// </summary>
        internal static PermissionSet _UnsafeGetAssertPermSet()
        {
            // SEC_NOTE: All callers should already be guarded by EventLogPermission demand.
            PermissionSet permissionSet = new PermissionSet(PermissionState.None);

            // We need RegistryPermission 
            RegistryPermission registryPermission = new RegistryPermission(PermissionState.Unrestricted);
            permissionSet.AddPermission(registryPermission);

            // It is not enough to just assert RegistryPermission, for some regkeys
            // we need to assert EnvironmentPermission too
            EnvironmentPermission environmentPermission = new EnvironmentPermission(PermissionState.Unrestricted);
            permissionSet.AddPermission(environmentPermission);

            // For remote machine registry access UnmanagdCodePermission is required.
            SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
            permissionSet.AddPermission(securityPermission);

            return permissionSet;
        }

        /// <summary>
        /// Checks IPv4 validity
        /// </summary>
        public bool ValidateIPv4(string ipString)
        {
            if (String.IsNullOrWhiteSpace(ipString))
                return false;

            string[] splitValues = ipString.Split('.');
            if (splitValues.Length != 4)
                return false;

            byte tempForParsing;

            return splitValues.All(r => byte.TryParse(r, out tempForParsing));
        }

        private void ButtonCalcGUIDs_Click(object sender, RoutedEventArgs e)
        {
            calculateGUIDs();
        }

        /// <summary>
        /// Calculates GUIDs from FQDN hostnames.
        /// </summary>
        private void calculateGUIDs()
        {
            TextRange textRange = new TextRange(
               // TextPointer to the start of content in the RichTextBox.
               RichTextboxFQDNs.Document.ContentStart,
               // TextPointer to the end of content in the RichTextBox.
               RichTextboxFQDNs.Document.ContentEnd
           );
            // The Text property on a TextRange object returns a string
            // representing the plain text content of the TextRange.
            string fqdns = textRange.Text;
            string[] sbids = fqdns.Split(new Char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            if (sbids.Length > 0)
            {
                List<string> calculatedIDs = SunburstDomainDecoder.Decode(sbids);
                if (calculatedIDs.Count > 0)
                {
                    recurs = true;
                    RichTextboxFQDNs.Document.Blocks.Clear();
                    string calcFQDNs = string.Empty;
                    foreach (string sid in calculatedIDs)
                        calcFQDNs += sid + "\r\n";

                    RichTextboxFQDNs.Document.Blocks.Add(new Paragraph(new Run(calcFQDNs.TrimEnd())));
                    recurs = false;
                }
                Calculated = true;
            }
        }

        /// <summary>
        /// Prevents recursion loop on RichTextBox events
        /// </summary>
        bool recurs = false;

        private void RichTextboxFQDNs_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            if (!recurs)
            {
                recurs = true;
                Calculated = false;
                if (!ButtonCalcGUIDs.IsEnabled)
                    ButtonCalcGUIDs.IsEnabled = true;
                TextRange textRange = new TextRange(
                    // TextPointer to the start of content in the RichTextBox.
                    RichTextboxFQDNs.Document.ContentStart,
                    // TextPointer to the end of content in the RichTextBox.
                    RichTextboxFQDNs.Document.ContentEnd
                );
                textRange.ClearAllProperties();
                recurs = false;
            }
        }

        private void TextBox_IP_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            if (TextBox_IP.Text == "")
                Button_Remote.IsEnabled = false;
            else
                Button_Remote.IsEnabled = true;
        }

        private void ButtonManualGUID_Click(object sender, RoutedEventArgs e)
        {
            string id = Textbox_SBID.Text;
            if (id != "")
            {
                string sbguid = getSUNBURSTGUID(id);
                Textbox_GUID.Text = sbguid;

                IEnumerable<TextRange> wordRanges = GetAllWordRanges(RichTextboxFQDNs.Document);
                bool firstWord = true;
                recurs = true;
                foreach (TextRange wordRange in wordRanges)
                {
                    if (wordRange.Text == sbguid)
                    {
                        wordRange.ApplyPropertyValue(TextElement.BackgroundProperty, Brushes.Yellow);
                        wordRange.ApplyPropertyValue(TextElement.ForegroundProperty, Brushes.Crimson);
                        if (firstWord)
                        {
                            firstWord = false;
                            Rect r = wordRange.Start.GetCharacterRect(LogicalDirection.Backward);
                            RichTextboxFQDNs.ScrollToVerticalOffset(r.Y);
                        }

                    }
                }
                recurs = false;
            }
        }
    }
}
