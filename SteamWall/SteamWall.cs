using System;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace SteamStealerBlock
{
    class SteamStealerBlock
    {
        static void Main()
        {
            /* Create list of IPs to whitelist and give steamcommunity.com a static IP */
            IPAddress steamIP = Dns.GetHostAddresses("steamcommunity.com")[0];
            List<string> ipRanges = RangesExcluding(steamIP);
            string whitelist = String.Join(",", ipRanges);

            using (StreamWriter sw = File.AppendText(@"C:\Windows\System32\drivers\etc\hosts"))
            {
                sw.WriteLine();
                sw.WriteLine("127.0.0.1 api.steampowered.com");
                sw.WriteLine(String.Format("{0} steamcommunity.com", steamIP));
            }

            ProcessStartInfo procStartInfo = new ProcessStartInfo("netsh", String.Format("advfirewall firewall add rule name=\"Allow access to the internet\" dir=out action=allow remoteip={0} enable=yes", whitelist));
            procStartInfo.UseShellExecute = false;
            procStartInfo.CreateNoWindow = true;
            Process.Start(procStartInfo);
            procStartInfo = new ProcessStartInfo("netsh", "advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound");
            procStartInfo.UseShellExecute = false;
            procStartInfo.CreateNoWindow = true;
            Process.Start(procStartInfo);

            string line;
            System.IO.StreamReader file = new System.IO.StreamReader(@"whitelist.txt");
            while((line = file.ReadLine()) != null)
            {
                procStartInfo = new ProcessStartInfo("netsh", String.Format("advfirewall firewall add rule name=\"Allow Steam for {1}\" dir=out action=allow program=\"{1}\" remoteip={0}/32 enable=yes", steamIP, line));
                procStartInfo.UseShellExecute = false;
                procStartInfo.CreateNoWindow = true;
                Process.Start(procStartInfo);
            }
            Console.WriteLine("Successfully changed firewall settings. Press enter to continue.");
        }

        private static Int64 ConvertToLong(IPAddress a)
        {
            byte[] addressBits = a.GetAddressBytes();
            Int64 retval = 0;
            for (int i = 0; i < addressBits.Length; i++)
            {
                retval = (retval << 8) + (int)addressBits[i];
            }

            return retval;
        }

        private static IPAddress ConvertToIP(long a)
        {
            return IPAddress.Parse(a.ToString());
        }

        private static IPAddress IncrementIP(IPAddress a, long b)
        {
            return ConvertToIP(ConvertToLong(a) + b);
        }

        private static IPAddress DecrementIP(IPAddress a, long b)
        {
            return ConvertToIP(ConvertToLong(a) - b);
        }

        private static Int64 Difference(IPAddress a, IPAddress b)
        {
            return Math.Abs(ConvertToLong(a) - ConvertToLong(b));
        }

        private static List<string> RangesTo(IPAddress a)
        {
            IPAddress startingIP = new IPAddress(new byte[] { 0, 0, 0, 0 });

            List<string> ipRanges = new List<string>();
            while (ConvertToLong(startingIP) < ConvertToLong(a))
            {
                /* Find a number of hosts between those two addresses */
                long difference = Difference(startingIP, a);
                /* Find a mask to cover most of those hosts */
                double mask = 32 - Math.Floor(Math.Log(difference, 2));
                if (double.IsInfinity(mask))
                    mask = 32;

                string ipRange = String.Format("{0}/{1}", startingIP, mask);
                ipRanges.Add(ipRange);
                long hosts = (long)Math.Pow(2, 32 - mask);
                startingIP = IncrementIP(startingIP, hosts);
            }
            return ipRanges;
        }

        private static List<string> RangesFrom(IPAddress a)
        {
            IPAddress endingIP = new IPAddress(new byte[] { 255, 255, 255, 255 });

            List<string> ipRanges = new List<string>();
            while (ConvertToLong(a) < ConvertToLong(endingIP))
            {
                /* Find a number of hosts between those two addresses */
                long difference = Difference(endingIP, a);
                /* Find a mask to cover most of those hosts */
                double mask = 32 - Math.Floor(Math.Log(difference, 2));
                if (double.IsInfinity(mask))
                    mask = 32;

                long hosts = (long)Math.Pow(2, 32 - mask);
                endingIP = DecrementIP(endingIP, hosts);

                string ipRange = String.Format("{0}/{1}", IncrementIP(endingIP, 1), mask);
                ipRanges.Add(ipRange);
            }
            return ipRanges;
        }
        
        private static List<string> RangesExcluding(IPAddress a)
        {
            IPAddress endingIP = new IPAddress(new byte[] { 255, 255, 255, 255 });

            List<string> ipRanges = new List<string>();
            ipRanges.AddRange(RangesTo(a));
            ipRanges.AddRange(RangesFrom(a));
            return ipRanges;
        }
    }
}
