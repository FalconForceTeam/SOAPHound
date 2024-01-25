using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using CommandLine.Text;

namespace SOAPHound
{
    public class Options
    {
        //Connection Options
        [Option(HelpText = "Username to use for ADWS Connection. Format: domain\\user or user@domain", Default = null)]
        public string User { get; set; }

        [Option(HelpText = "Password to use for ADWS Connection",  Default = null)]
        public string Password { get; set; }

        [Option(HelpText = "Specify domain for enumeration",  Default = null)]
        public string Domain { get; set; }

        [Option(HelpText = "Domain Controller to connect to",  Default = null)]
        public string DC { get; set; }

        //Supported modes 
        [Option(HelpText = "Only build cache and not perform further actions", Group = "Mode", Default = false)]
        public bool BuildCache { get; set; }

        [Option(HelpText = "Show stats of local cache file", Group = "Mode", Default = null)]
        public bool ShowStats { get; set; }

        [Option(HelpText = "Dump AD Integrated DNS data", Group = "Mode", Default = false)]
        public bool DNSDump { get; set; }

        [Option(HelpText = "Dump AD Certificate Services data", Group = "Mode", Default = false)]
        public bool CertDump { get; set; }

        [Option(HelpText = "Dump BH data", Group = "Mode", Default = false)]
        public bool BHDump { get; set; }

        //Functional Options
        [Option('a',"autosplit",HelpText = "Enable AutoSplit mode: automatically split object retrieval on two depth levels based on defined trheshold", Default = false)]
        public bool AutoSplit { get; set; }
        [Option('t', "threshold", HelpText = "AutoSplit mode: Define split threshold based on number of objects per starting letter", Default = 0)]
        public int Threshold { get; set; }
        [Option(HelpText = "Do not request LAPS related information", Default = false)]
        public bool NoLAPS { get; set; }
        //Output Options
        [Option('o',"outputdirectory",HelpText = "Folder to output files to (full path needed)", Default = null)]
        public string OutputDirectory { get; set; }
        [Option('c',"cachefilename", HelpText = "Filename for the cache file (full path needed)", Default = null)]
        public string CacheFileName { get; set; }
        [Option(HelpText = "Create log file", Default = null )]
        public string LogFile { get; set; }
    }
}
