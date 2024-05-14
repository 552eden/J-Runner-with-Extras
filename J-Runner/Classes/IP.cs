using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using System.Security.Cryptography;

namespace JRunner
{
    class IP
    {
        private static string cpukey = "";
        private static int ldvvalue = 0;
        static List<string> ip = new List<string>();
        static bool found = false;
        static string localGatewayIp = "?";



        static string CalculateMD5(string filePath)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    // Compute MD5 hash of the file stream
                    byte[] hashBytes = md5.ComputeHash(stream);

                    // Convert the byte array to hexadecimal string
                    StringBuilder sb = new StringBuilder();
                    foreach (byte b in hashBytes)
                    {
                        sb.Append(b.ToString("x2"));
                    }
                    return sb.ToString();
                }
            }
        }

        // Function to select a file
        static string SelectFile()
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();

            // Set initial directory (optional)
            openFileDialog.InitialDirectory = Environment.CurrentDirectory;

            // Set the title of the dialog
            openFileDialog.Title = "Select a File";

            // Filter for specific file types (optional)
            openFileDialog.Filter = "Nand Files (*.bin)|*.bin|All files (*.*)|*.*";

            // Show the dialog and check if the user clicked OK
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                // Get the selected file name
                return openFileDialog.FileName;
            }
            else
            {
                // User canceled the operation
                return null;
            }
        }

        // Function to save a file
        static string saveFile()
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();

            // Set initial directory (optional)
            saveFileDialog.InitialDirectory = Environment.CurrentDirectory;

            // Set the title of the dialog
            saveFileDialog.Title = "Save File As";

            // Filter for specific file types (optional)
            saveFileDialog.Filter = "Nand Files (*.bin)|*.bin|All files (*.*)|*.*";

            // Show the dialog and check if the user clicked OK
            if (saveFileDialog.ShowDialog() == DialogResult.OK)
            {
                // Get the selected file name
                return saveFileDialog.FileName;
            }
            else
            {
                // User canceled the operation
                return null;
            }
        }

        static void printIP()
        {
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (NetworkInterface networkInterface in networkInterfaces)
            {
                Console.WriteLine($"Interface: {networkInterface.Name}");

                IPInterfaceProperties ipProperties = networkInterface.GetIPProperties();
                foreach (UnicastIPAddressInformation ip in ipProperties.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) // Check for IPv4 address
                    {
                        Console.WriteLine($"  IPv4 Address: {ip.Address}");
                    }
                }
                Console.WriteLine();
            }
        }

        static int sendFileToXbox(Socket clientSocket)
        {
            string filename = "";
            Console.WriteLine("Overriding file name with users choice");

            try
            {
                Thread thread = new Thread(() => filename = SelectFile());
                thread.SetApartmentState(ApartmentState.STA); //Set the thread to STA
                thread.Start();
                thread.Join(); //Wait for the thread to end
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

            if (!string.IsNullOrEmpty(filename))
            {
                Console.WriteLine($"Selected file: {filename}");
                // Process the selected file here
            }
            else
            {
                Console.WriteLine("Operation canceled.");
                // Clean up
                clientSocket.Shutdown(SocketShutdown.Both);
                clientSocket.Close();
                return 0;
            }
            Console.WriteLine($"Selected file: {Path.GetFileName(filename)}");

            // Calculate MD5 hash
            string md5Hash = CalculateMD5(filename);

            // Print the result
            Console.WriteLine("MD5 hash of the file:");
            Console.WriteLine(md5Hash);


            // Send the expected file size
            FileInfo fileInfo = new FileInfo(filename);
            byte[] sizeBuffer = System.Text.Encoding.ASCII.GetBytes(fileInfo.Length.ToString());
            clientSocket.Send(sizeBuffer);
            Console.WriteLine("file size sent is: {0}", fileInfo.Length.ToString());

            // Open the file
            FileStream fileStream = new FileStream(filename, FileMode.Open, FileAccess.Read);

            // Send the file
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                clientSocket.Send(buffer, bytesRead, SocketFlags.None);
            }

            Console.WriteLine("File sent successfully");
            fileStream.Close();
            System.Threading.Thread.Sleep(500);
            // Send the MD5
            byte[] sentMD5 = System.Text.Encoding.ASCII.GetBytes(md5Hash);
            clientSocket.Send(sentMD5);
            Console.WriteLine("MD5 Sent is: {0}", md5Hash);


            // Clean up
            clientSocket.Shutdown(SocketShutdown.Both);
            clientSocket.Close();

            return 1;
        }


        static int recieveFileFromXbox(Socket clientSocket)
        {
            string filename = "";
            Console.WriteLine("Overriding file name with users choice");
            int md5same = 0;

            try
            {
                Thread thread = new Thread(() => filename = saveFile());
                thread.SetApartmentState(ApartmentState.STA); //Set the thread to STA
                thread.Start();
                thread.Join(); //Wait for the thread to end
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

            if (!string.IsNullOrEmpty(filename))
            {
                Console.WriteLine($"Selected file: {filename}");
                // Process the selected file here
            }
            else
            {
                Console.WriteLine("Operation canceled.");
                // Clean up
                clientSocket.Shutdown(SocketShutdown.Both);
                clientSocket.Close();
                return 0;
            }
            Console.WriteLine($"Selected file: {Path.GetFileName(filename)}");

            try
            {
                // Send the start message
                byte[] startMessage = Encoding.ASCII.GetBytes("START_TRANSMISSION");
                clientSocket.Send(startMessage);




                // Receive file size
                byte[] fileSizeBuffer = new byte[4];
                clientSocket.Receive(fileSizeBuffer, 4, SocketFlags.None);
                int fileSize = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(fileSizeBuffer, 0));
                Console.WriteLine("Received file size: " + fileSize);

                // Receive additional data (string)
                byte[] additionalDataLengthBuffer = new byte[4];
                clientSocket.Receive(additionalDataLengthBuffer, 4, SocketFlags.None);
                int additionalDataLength = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(additionalDataLengthBuffer, 0));
                byte[] additionalDataBuffer = new byte[additionalDataLength];
                clientSocket.Receive(additionalDataBuffer, additionalDataLength, SocketFlags.None);
                string additionalData = Encoding.ASCII.GetString(additionalDataBuffer);
                Console.WriteLine("Received additional data: " + additionalData);

                // Receive file data
                using (FileStream fileStream = new FileStream(filename, FileMode.Create, FileAccess.Write))
                {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    int totalBytesRead = 0;
                    while ((bytesRead = clientSocket.Receive(buffer, 1024, SocketFlags.None)) > 0)
                    {
                        fileStream.Write(buffer, 0, bytesRead);
                        totalBytesRead += bytesRead;
                        if (totalBytesRead >= fileSize)
                            break;
                    }
                    Console.WriteLine("Received file data");
                }

                // Calculate MD5 hash
                string md5Hash = CalculateMD5(filename);

                if (md5Hash == additionalData)
                {
                    Console.WriteLine("Hashes are the same! Hash: {0}", md5Hash);
                    md5same = 1;
                    clientSocket.Shutdown(SocketShutdown.Both);
                    clientSocket.Close();
                    return 1;
                }
                else
                {
                    Console.WriteLine("hashes are not the same!");
                    Console.WriteLine("calculated Hash: {0}", md5Hash);
                    Console.WriteLine("Recived Hash: {0} ", additionalData);
                    clientSocket.Shutdown(SocketShutdown.Both);
                    clientSocket.Close();
                    return 0;
                }
            }
            catch (SocketException ex)
            {
                Console.WriteLine("SocketException: " + ex.ErrorCode + ", " + ex.Message);
                Console.WriteLine("Socket closed from xbox 360 side, this should be fine");
                if (md5same == 1) { return 1; }
                else
                {
                    return 0;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                return 0;
            }

        }

        public int socket_on = 0;
        Socket listener;

        public void nandOverIP()
        {


            int port = 4343;
            IPAddress ipAddr = IPAddress.Any;
            IPEndPoint localEndPoint = new IPEndPoint(ipAddr, port);
            listener = new Socket(ipAddr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            socket_on = 1;
            Console.WriteLine("your IP addresses are:");
            printIP();
            Console.WriteLine("please use the IP in the same network as your xbox");
            int sentFileResult = 0;
            int recievedFileResult = 0;
            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(10);

                Console.WriteLine("Waiting for incoming connections...");

                while (true)
                {
                    Socket clientSocket = listener.Accept();
                    Console.WriteLine("Accepted new connection from {0}", clientSocket.RemoteEndPoint);
                    // Receive the filename to check if we need to send file or rceieve it

                    byte[] filenameBuffer = new byte[1024];
                    int bytesReceived = clientSocket.Receive(filenameBuffer);
                    string filename = System.Text.Encoding.ASCII.GetString(filenameBuffer, 0, bytesReceived);


                    Console.WriteLine("file name test");
                    Console.WriteLine(filename);
                    Console.WriteLine("end filename test");
                    Console.WriteLine("Received filename: {0}", filename);
                    if (filename == "game:\\updflash.bin")
                    {
                        sentFileResult = sendFileToXbox(clientSocket);
                        if (sentFileResult == 1) { Console.WriteLine("sent file seccesfully"); }
                        else { Console.WriteLine("error sending file"); }
                    }
                    else if (filename == "game:\\flashdmp.bin")
                    {
                        recievedFileResult = recieveFileFromXbox(clientSocket);
                        if (recievedFileResult == 1) { Console.WriteLine("recieved file seccesfully"); }
                        else { Console.WriteLine("error sending file"); }

                    }


                }
            }
            catch (SocketException ex) when (ex.ErrorCode == 10004) // WSAEINTR
            {
                Console.WriteLine("Server closed succefully");
            }
            catch (SocketException ex)
            {
                // Handle other socket exceptions if needed
                Console.WriteLine($"Socket exception: {ex.Message}");
            }
            catch (Exception ex)
            {
                // Handle other exceptions
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }

        public void closeSocket()
        {
            this.listener.Close();
            socket_on = 0;
        }
    


        string getarptable()
        {
            sendAsyncPingPacket(changelastquad(localGatewayIp, "255"));
            string sResults = "";
            System.Diagnostics.ProcessStartInfo ps = new System.Diagnostics.ProcessStartInfo("arp", "-a");
            ps.CreateNoWindow = true;
            ps.UseShellExecute = false;
            ps.RedirectStandardOutput = true;
            using (System.Diagnostics.Process proc = new System.Diagnostics.Process())
            {
                proc.StartInfo = ps;
                proc.Start();
                System.IO.StreamReader sr = proc.StandardOutput;
                while (!proc.HasExited) ;
                sResults = sr.ReadToEnd();
            }
            return sResults;
        }
        string parsearp(string mac, string table)
        {
            if (variables.debugMode) Console.WriteLine(mac);
            if (mac == "nomac") return "0.0.0.0";
            string[] values = table.Split('\n');
            string ip = "0.0.0.0";
            foreach (string val in values)
            {
                if (val.ToLower().Contains(mac.ToLower()))
                {
                    if (variables.debugMode) Console.WriteLine(val);
                    foreach (string lo in val.Split(' '))
                    {
                        if (IsIPv4(lo)) ip = lo;
                    }
                    if (variables.debugMode) Console.WriteLine(ip);
                }
            }
            return ip;
        }
        string getmacaddress()
        {
            if (!File.Exists(variables.filename1)) return "nomac";
            byte[] smc_config;
            int block_offset;
            smc_config = Nand.Nand.getsmcconfig(variables.filename1, out block_offset);
            string mac = Regex.Replace(Oper.ByteArrayToString(Oper.returnportion(smc_config, 0x220 + block_offset, 6)), @"(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})", @"$1-$2-$3-$4-$5-$6");
            return mac;
        }

        public string IP_GetCpuKey(string ip, int saveDir = 0)
        {
            ldvvalue = 0;
            cpukey = "";
            string folder = variables.outfolder;
            if (saveDir == 2) folder = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            else if (saveDir == 1) folder = MainForm.mainForm.getCurrentWorkingFolder();
            if (File.Exists(Path.Combine(folder, "Fuses.txt"))) File.Delete(Path.Combine(folder, "Fuses.txt"));
            string fuses = ("http://" + ip + @"/FUSE");
            WebClient Client = new WebClient();
            try
            {
                string page = Client.DownloadString("http://" + ip);
                string regex = @"(?<=<title.*>)([\s\S]*)(?=</title>)";
                Regex ex = new Regex(regex, RegexOptions.IgnoreCase);
                if (variables.debugMode) Console.WriteLine(ex.Match(page).Value.Trim());
                Console.WriteLine("Contacting {0}...", ip);
                if (ex.Match(page).Value.Trim().Contains("Reloaded"))
                {
                    string fuse = Client.DownloadString(fuses);
                    string[] fuseArr = Regex.Split(fuse, "\n");
                    foreach (char c in fuseArr[7].Substring(fuseArr[7].IndexOf(':')))
                    {
                        if (c == 'f') ldvvalue++;
                    }
                    foreach (char c in fuseArr[8].Substring(fuseArr[8].IndexOf(':')))
                    {
                        if (c == 'f') ldvvalue++;
                    }
                    StreamWriter SW = File.AppendText(Path.Combine(folder, "Fuses.txt"));
                    foreach (string oi in fuseArr)
                    {
                        SW.WriteLine(oi);
                    }
                    string cpukeytag = page.Substring(page.IndexOf("CPU Key:"), 70);
                    if (variables.debugMode) Console.WriteLine("Cpukey before edit: {0}", cpukeytag);
                    cpukey = cpukeytag.Substring(cpukeytag.IndexOf("<td>") + 4, 32);
                    variables.cpukey = cpukey;
                    if (variables.debugMode) Console.WriteLine("Cpukey: {0}", cpukey);
                    string dvdkeytag = page.Substring(page.IndexOf("DVD Key:"), 70);
                    if (variables.debugMode) Console.WriteLine("DVDkey before edit: {0}", dvdkeytag);

                    cpukeytag = StripTagsCharArray(cpukeytag);
                    dvdkeytag = StripTagsCharArray(dvdkeytag);
                    if (variables.debugMode) Console.WriteLine("Cpukey after edit: {0}", cpukeytag);
                    if (variables.debugMode) Console.WriteLine("dvdkey after edit: {0}", dvdkeytag);

                    Console.WriteLine("6BL Lockdown Value: {0}", ldvvalue);

                    SW.WriteLine("");
                    SW.WriteLine(cpukeytag);
                    SW.WriteLine(dvdkeytag);
                    MainForm._event1.Set();
                    SW.Close();
                }
                else if (ex.Match(page).Value.Trim().Contains("XeLLous"))
                {
                    string cpukeytag = page.Substring(page.IndexOf("CPU"), 70);
                    if (variables.debugMode) Console.WriteLine("Cpukey before edit: {0}", cpukeytag);
                    cpukey = cpukeytag.Substring(cpukeytag.IndexOf("<td>") + 4, 32);
                    variables.cpukey = cpukey;
                    if (variables.debugMode) Console.WriteLine("Cpukey: {0}", cpukey);

                    cpukeytag = StripTagsCharArray(cpukeytag);
                    if (variables.debugMode) Console.WriteLine("Cpukey after edit: {0}", cpukeytag);
                    string fuse = Client.DownloadString(fuses);
                    string[] fuseArr = Regex.Split(fuse, "\n");
                    foreach (char c in fuseArr[8].Substring(fuseArr[8].IndexOf(':')))
                    {
                        if (c == 'f') ldvvalue++;
                    }
                    foreach (char c in fuseArr[9].Substring(fuseArr[9].IndexOf(':')))
                    {
                        if (c == 'f') ldvvalue++;
                    }

                    Console.WriteLine("6BL Lockdown Value: {0}", ldvvalue); 

                    StreamWriter SW = File.AppendText(Path.Combine(folder, "Fuses.txt"));
                    for (int i = 1; i < fuseArr.Count(); i++)
                    {
                        SW.WriteLine(fuseArr[i]);
                    }
                    SW.Close();
                    MainForm._event1.Set();
                }
            }
            catch (System.Net.WebException) { Console.WriteLine("Connection Timeout"); return cpukey; }
            catch (Exception ex) { Console.WriteLine(ex.Message); return cpukey; }
            if (variables.debugMode) Console.WriteLine("Finished");
            return cpukey;
        }



        public string IP_GetCpuKey(string ip, bool print, int saveDir = 0)
        {
            ldvvalue = 0;
            cpukey = "";
            if (variables.debugMode) Console.WriteLine(ip);
            string folder = variables.outfolder;
            if (saveDir == 2) folder = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            else if (saveDir == 1) folder = MainForm.mainForm.getCurrentWorkingFolder();
            if (File.Exists(Path.Combine(folder, "Fuses.txt"))) File.Delete(Path.Combine(folder, "Fuses.txt"));
            string fuses = ("http://" + ip + @"/FUSE");
            WebClient Client = new WebClient();
            try
            {
                string page = Client.DownloadString("http://" + ip);
                string regex = @"(?<=<title.*>)([\s\S]*)(?=</title>)";
                Regex ex = new Regex(regex, RegexOptions.IgnoreCase);
                if (variables.debugMode) Console.WriteLine(ex.Match(page).Value.Trim());
                if (print) Console.WriteLine("Contacting {0}...", ip);
                if (ex.Match(page).Value.Trim().Contains("Reloaded"))
                {
                    found = true;
                    Console.WriteLine("Found Xbox in XeLL: {0}", ip);

                    string fuse = Client.DownloadString(fuses);
                    string[] fuseArr = Regex.Split(fuse, "\n");
                    foreach (char c in fuseArr[7].Substring(fuseArr[7].IndexOf(':')))
                    {
                        if (c == 'f') ldvvalue++;
                    }
                    foreach (char c in fuseArr[8].Substring(fuseArr[8].IndexOf(':')))
                    {
                        if (c == 'f') ldvvalue++;
                    }
                    StreamWriter SW = File.AppendText(Path.Combine(folder, "Fuses.txt"));
                    foreach (string oi in fuseArr)
                    {
                        SW.WriteLine(oi);
                    }
                    string cpukeytag = page.Substring(page.IndexOf("CPU Key:"), 70);
                    if (variables.debugMode) Console.WriteLine("Cpukey before edit: {0}", cpukeytag);
                    cpukey = cpukeytag.Substring(cpukeytag.IndexOf("<td>") + 4, 32);
                    variables.cpukey = cpukey;
                    if (variables.debugMode) Console.WriteLine("Cpukey: {0}", cpukey);
                    string dvdkeytag = page.Substring(page.IndexOf("DVD Key:"), 70);
                    if (variables.debugMode) Console.WriteLine("DVDkey before edit: {0}", dvdkeytag);

                    cpukeytag = StripTagsCharArray(cpukeytag);
                    dvdkeytag = StripTagsCharArray(dvdkeytag);
                    if (variables.debugMode) Console.WriteLine("Cpukey after edit: {0}", cpukeytag);
                    if (variables.debugMode) Console.WriteLine("dvdkey after edit: {0}", dvdkeytag);

                    Console.WriteLine("6BL Lockdown Value: {0}", ldvvalue);

                    SW.WriteLine("");
                    SW.WriteLine(cpukeytag);
                    SW.WriteLine(dvdkeytag);
                    MainForm._event1.Set();
                    SW.Close();
                }
                else if (ex.Match(page).Value.Trim().Contains("XeLLous"))
                {
                    found = true;
                    Console.WriteLine("Found Xbox in XeLL: {0}", ip);

                    string cpukeytag = page.Substring(page.IndexOf("CPU"), 70);
                    if (variables.debugMode) Console.WriteLine("Cpukey before edit: {0}", cpukeytag);
                    cpukey = cpukeytag.Substring(cpukeytag.IndexOf("<td>") + 4, 32);
                    variables.cpukey = cpukey;
                    if (variables.debugMode) Console.WriteLine("Cpukey: {0}", cpukey);

                    cpukeytag = StripTagsCharArray(cpukeytag);
                    if (variables.debugMode) Console.WriteLine("Cpukey after edit: {0}", cpukeytag);
                    string fuse = Client.DownloadString(fuses);
                    string[] fuseArr = Regex.Split(fuse, "\n");
                    foreach (char c in fuseArr[8].Substring(fuseArr[8].IndexOf(':')))
                    {
                        if (c == 'f') ldvvalue++;
                    }
                    foreach (char c in fuseArr[9].Substring(fuseArr[9].IndexOf(':')))
                    {
                        if (c == 'f') ldvvalue++;
                    }

                    Console.WriteLine("6BL Lockdown Value: {0}", ldvvalue);

                    StreamWriter SW = File.AppendText(Path.Combine(folder, "Fuses.txt"));
                    for (int i = 1; i < fuseArr.Count(); i++)
                    {
                        SW.WriteLine(fuseArr[i]);
                    }
                    SW.Close();
                    MainForm._event1.Set();
                }
            }
            catch (System.Net.WebException) { if (print) Console.WriteLine("Connection Timeout"); return cpukey; }
            catch (Exception ex) { if (print) Console.WriteLine(ex.ToString()); return cpukey; }
            return cpukey;
        }



        static bool IsIPv4(string value)
        {
            var quads = value.Split('.');

            // if we do not have 4 quads, return false
            if (quads.Length != 4) return false;

            // for each quad
            foreach (var quad in quads)
            {
                int q;
                // if parse fails 
                // or length of parsed int != length of quad string (i.e.; '1' vs '001')
                // or parsed int < 0
                // or parsed int > 255
                // return false
                if (!Int32.TryParse(quad, out q)
                    || !q.ToString().Length.Equals(quad.Length)
                    || q < 0
                    || q > 255) { return false; }

            }

            return true;
        }
        static string changelastquad(string ip, string lastquad)
        {
            string[] quads = ip.Split('.');
            if (quads.Length != 4) return "0.0.0.0";
            quads[3] = lastquad;
            return String.Join(".", quads);
        }

        public static string getGatewayIp()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            string address;
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    address = ip.ToString();
                    return address.Substring(0, address.LastIndexOf('.') + 1);
                }
            }
            return "?";
        }

        public static void initaddresses()
        {
            if (string.IsNullOrWhiteSpace(variables.ipPrefix))
            {
                localGatewayIp = getGatewayIp();
            }
            else
            {
                localGatewayIp = variables.ipPrefix + ".0";
            }

            if (!IsIPv4(variables.ipStart))
            {
                if (localGatewayIp != "?")
                {
                    variables.ipStart = changelastquad(localGatewayIp, "0");
                }
            }
            if (!IsIPv4(variables.ipEnd))
            {
                if (localGatewayIp != "?")
                {
                    variables.ipEnd = changelastquad(localGatewayIp, "255");
                }
            }
        }

        private void sendAsyncPingPacket(string hostToPing)
        {
            try
            {
                int timeout = 100;
                Ping pingPacket = new Ping();
                AutoResetEvent waiter = new AutoResetEvent(false);
                pingPacket.PingCompleted += new PingCompletedEventHandler(PingCompletedCallback);
                string data = "Ping test check";
                byte[] byteBuffer = Encoding.ASCII.GetBytes(data);
                PingOptions pingOptions = new PingOptions(255, true);
                pingPacket.SendAsync(hostToPing, timeout, byteBuffer, pingOptions, waiter);
            }
            catch (PingException)
            {
                Console.WriteLine("INVALID IP ADDRESS FOUND");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exceptin " + ex.Message);
            }
        }
        private void PingCompletedCallback(object sender, PingCompletedEventArgs e)
        {
            try
            {
                if (e.Cancelled)
                {
                    Console.WriteLine("Ping canceled.");
                    ((AutoResetEvent)e.UserState).Set();
                }
                if (e.Error != null)
                {
                    Console.WriteLine("Ping failed>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ");
                    ((AutoResetEvent)e.UserState).Set();
                }

                PingReply reply = e.Reply;

                if (reply.Status == IPStatus.Success)
                {
                    if (!ip.Contains(reply.Address.ToString())) ip.Add(reply.Address.ToString());
                }
                ((AutoResetEvent)e.UserState).Set();
            }
            catch (PingException)
            {
                Console.WriteLine("INVALID IP ADDRESS");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception " + ex.Message);
            }
        }
        public void DisplayReply(PingReply reply)
        {
            if (reply == null)
                return;

            //Console.WriteLine("ping status: {0}", reply.Status);
            if (reply.Status == IPStatus.Success)
            {
                Console.WriteLine("Address: {0}", reply.Address.ToString());
                Console.WriteLine("RoundTrip time: {0}", reply.RoundtripTime);
                Console.WriteLine("Time to live: {0}", reply.Options.Ttl);
                Console.WriteLine("Don't fragment: {0}", reply.Options.DontFragment);
                Console.WriteLine("Buffer size: {0}", reply.Buffer.Length);
            }
        }
        private long ToInt(string addr)
        {

            return (uint)System.Net.IPAddress.NetworkToHostOrder(
                BitConverter.ToInt32(IPAddress.Parse(addr).GetAddressBytes(), 0));
        }
        private string ToAddr(long address)
        {
            return System.Net.IPAddress.Parse(address.ToString()).ToString();
        }
        private void scanLiveHosts(string ipFrom, string ipTo, ProgressBar pb)
        {
            long from = ToInt(ipFrom);
            long to = ToInt(ipTo);
            int i;
            long ipLong = ToInt(ipFrom);
            while (ipLong < to)
            {
                i = ((int)(ipLong - from) * pb.Maximum) / (int)(to - from);
                pb.BeginInvoke(new Action(() => pb.Value = i));
                string address = ToAddr(ipLong);
                sendAsyncPingPacket(address);
                sendAsyncPingPacket(address);
                sendAsyncPingPacket(address);
                sendAsyncPingPacket(address);
                Thread.Sleep(5);
                ipLong++;
            }
            pb.BeginInvoke(new Action(() => pb.Value = pb.Maximum));
        }

        public string getkey()
        {
            return cpukey;
        }
        public int getldv()
        {
            return ldvvalue;
        }

        public void IPScanner(ProgressBar pb)
        {
            found = false;
            initaddresses();
            variables.isscanningip = true;
            try
            {
                IP_GetCpuKey(parsearp(getmacaddress(), getarptable()), false);
            }
            catch (Exception ex) { if (variables.debugMode) Console.WriteLine(ex.ToString()); }
            if (found)
            {
                Console.WriteLine("");
                variables.isscanningip = false;
                return;
            }
            bool use = false;
            Console.WriteLine("Scan Stage 1: Finding IPs...");
            scanLiveHosts(variables.ipStart, variables.ipEnd, pb);
            Thread.Sleep(500);
            found = false;
            Console.WriteLine("Scan Stage 2: Searching IPs...");
            pb.BeginInvoke(new Action(() => pb.Value = pb.Minimum));
            foreach (string o in ip)
            {
                IPAddress myScanIP = IPAddress.Parse(o);
                IPHostEntry myScanHost = null;
                try
                {
                    if (use) myScanHost = Dns.GetHostEntry(myScanIP);
                }
                catch (Exception ex) { Console.WriteLine(ex.Message); }
                if (myScanHost != null)
                {
                    Console.WriteLine(myScanHost.HostName.ToString() + "\t");
                }
                pb.BeginInvoke(new Action(() => pb.Value = pb.Value + (100 / (ip.Count + 1))));
                if (o != localGatewayIp) IP_GetCpuKey(o, false);
                if (found) break;
            }

            pb.BeginInvoke(new Action(() => pb.Value = pb.Maximum));
            if (!found) Console.WriteLine("No Xbox in XeLL detected");
            Console.WriteLine("");
            variables.isscanningip = false;
        }

        public string DownloadWebPage(string Url)
        {
            // Open a connection
            HttpWebRequest WebRequestObject = (HttpWebRequest)HttpWebRequest.Create(new Uri(Url));

            // You can also specify additional header values like 
            // the user agent or the referer:
            WebRequestObject.UserAgent = ".NET Framework/2.0";

            // Request response:
            WebResponse Response = WebRequestObject.GetResponse();

            // Open data stream:
            Stream WebStream = Response.GetResponseStream();

            // Create reader object:
            StreamReader Reader = new StreamReader(WebStream);

            // Read the entire stream content:
            string PageContent = Reader.ReadToEnd();

            // Cleanup
            Reader.Close();
            WebStream.Close();
            Response.Close();

            return PageContent;
        }
        public string StripTagsCharArray(string source)
        {
            char[] array = new char[source.Length];
            int arrayIndex = 0;
            bool inside = false;

            for (int i = 0; i < source.Length; i++)
            {
                char let = source[i];
                if (let == '<')
                {
                    inside = true;
                    continue;
                }
                if (let == '>')
                {
                    inside = false;
                    continue;
                }
                if (!inside)
                {
                    array[arrayIndex] = let;
                    arrayIndex++;
                }
            }
            return new string(array, 0, arrayIndex);
        }
    }
}
