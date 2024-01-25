using System;
using System.IO;
using System.Net;
using System.Diagnostics;
using System.Net.NetworkInformation;
using CommandLine;
using CommandLine.Text;
using System.Collections.Generic;
using Newtonsoft.Json;
using SOAPHound.ADWS;
using SOAPHound.Enums;
using SOAPHound.Processors;
using System.Linq;

namespace SOAPHound
{
    public class Program
    {
        public string Server = null;
        public int Port = 9389;
        public NetworkCredential Credential = null;
        public Boolean dnsdump = false;
        public Boolean certdump = false;
        public Boolean bhdump = false;
        public Boolean deep = false;
        public string c1 = "abcdefghijklmnopqrstuvwxyz0123456789";
        public string c2 = "abcdefghijklmnopqrstuvwxyz0123456789";
        public Boolean autosplit = false;
        public int threshold = 0;
        public Boolean showStats = false;
        public Boolean buildcacheonly = false;
        public Boolean outputitems = false;
        public Boolean nolaps = false;
        public string[] properties = null;
        public string ldapfilter = null;
        public string ldapbase = null;
        public string domainName = null;
        public string cacheFileName = null;
        public string outputDirectory = null;

        public static void Main(string[] args)
        {
            Program program = new Program();
            program.ParseCommandLineArgs(args);
        }

        private string GetCurrentDomain()
        {
            return IPGlobalProperties.GetIPGlobalProperties().DomainName;
        }

        private void EnableLogFile(string logfile)
        {
            Trace.AutoFlush = true;
            TextWriterTraceListener listener = new TextWriterTraceListener(logfile);
            Trace.Listeners.Add(listener);
        }

        void ParseCommandLineArgs(string[] args)
        {

            Trace.WriteLine("Before parsing arguments");

            var parser = new Parser(with =>
            {
                with.CaseInsensitiveEnumValues = true;
                with.CaseSensitive = false;
                with.HelpWriter = null;
                with.AutoVersion = false;
            });

            var parserResult = parser.ParseArguments<Options>(args);
            parserResult
                .WithParsed<Options>(options => RunOptions(options))
                .WithNotParsed(errs => DisplayHelp(parserResult, errs));

        }

        void DisplayHelp<T>(ParserResult<T> result, IEnumerable<Error> errs)
        {
            var helpText = HelpText.AutoBuild(result, h =>
            {
                h.AdditionalNewLineAfterOption = false;
                h.Heading = "SOAPHound";
                h.Copyright = "Copyright (c) 2024 FalconForce";
                h.AutoVersion = false;
                h.MaximumDisplayWidth = 300;
                return HelpText.DefaultParsingErrorsHandler(result, h);
            }, e => e);
            Console.WriteLine(helpText);
        }

        public void DisplayErrorMessage(string text)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(text);
            Console.ResetColor();
        }

        private void RunOptions(Options options)
        {
            string user = null;
            string userdomain = null;
            string password = null;

            if (!string.IsNullOrEmpty(options.LogFile))
            {
                EnableLogFile(options.LogFile);
            }

            if (!(options.BuildCache || options.ShowStats || options.DNSDump || options.CertDump || options.BHDump))
            {
                DisplayErrorMessage("No valid mode has been selected. Please execute --help to select a valid mode.");
                return;
            }

            if (options.DNSDump || options.CertDump || options.BHDump)
            {
                if (String.IsNullOrEmpty(options.OutputDirectory))
                {

                    DisplayErrorMessage("Output directory is required. Use --outputdirectory");
                    return;
                }
                else
                {
                    outputDirectory = options.OutputDirectory.TrimEnd('\\') + "\\";
                }
            }

            if (!(options.ShowStats))
            {
                if (options.User != null)
                {
                    if (options.User.Contains("\\"))
                    {
                        int pos = options.User.IndexOf('\\');
                        userdomain = options.User.Substring(0, pos);
                        user = options.User.Substring(pos + 1);
                    }
                    else
                    {
                        user = options.User;
                        if (!user.Contains("@"))
                        {
                            DisplayErrorMessage("User must be in the format domain\\user or user@domain");
                        }
                    }
                }
                Server = options.DC;
                password = options.Password;

                if (String.IsNullOrEmpty(Server))
                {
                    Server = GetCurrentDomain();
                    if (String.IsNullOrEmpty(Server))
                    {
                        DisplayErrorMessage("Domain controller is missing, use --dc.");
                        return;
                    }
                }
                if (user != null)
                {
                    if (password == null)
                        DisplayErrorMessage("Password is missing, use --password.");
                    if (String.IsNullOrEmpty(userdomain))
                    {
                        Credential = new NetworkCredential(user, password);
                    }
                    else
                    {
                        Credential = new NetworkCredential(user, password, userdomain);
                    }
                }
            }

            if (options.DNSDump)
            {
                dnsdump = true;
            };

            if (options.ShowStats)
            {
                if (String.IsNullOrEmpty(options.CacheFileName))
                {
                    DisplayErrorMessage("Cache file name is missing, use --cachefilename.");
                    return;
                }
                autosplit = true;
                showStats = true;
                cacheFileName = options.CacheFileName;
            }

            if (options.BuildCache)
            {
                if (String.IsNullOrEmpty(options.CacheFileName))
                {
                    DisplayErrorMessage("Cache file name is missing, use --cachefilename.");
                    return;
                }
                buildcacheonly = true;
                cacheFileName = options.CacheFileName;
            }

            if (options.CertDump)
            {
                if (String.IsNullOrEmpty(options.CacheFileName))
                {
                    DisplayErrorMessage("Cache file name is missing, use --cachefilename.");
                    return;
                }
                certdump = true;
                cacheFileName = options.CacheFileName;
            }

            if (options.BHDump)
            {
                if (String.IsNullOrEmpty(options.CacheFileName))
                {
                    DisplayErrorMessage("Cache file name is missing, use --cachefilename.");
                    return;
                }
                if (options.AutoSplit)
                {
                    if (options.Threshold == 0)
                    {
                        DisplayErrorMessage("AutoSplit threshold is missing, use --threshold.");
                        return;
                    }

                }
                bhdump = true;
                cacheFileName = options.CacheFileName;
                autosplit = options.AutoSplit;
                threshold = options.Threshold;
                nolaps = options.NoLAPS;
            }

            domainName = options.Domain;
            domainName = string.IsNullOrEmpty(domainName) ? GetCurrentDomain() : domainName;
            if (string.IsNullOrEmpty(domainName))
            {
                DisplayErrorMessage("Domain is missing and could not be determined automatically, use --domain.");
                return;
            }
            Run(Server, Port, Credential);
            return;
        }

        public void Run(string Server, int Port, NetworkCredential Credential)
        {
            ADWSUtils.Server = Server;
            ADWSUtils.Port = Port;
            ADWSUtils.Credential = Credential;
            ADWSUtils.nolaps = nolaps;

            if (!string.IsNullOrEmpty(outputDirectory))
            {
                System.IO.Directory.CreateDirectory(outputDirectory);
            }
            if (!string.IsNullOrEmpty(cacheFileName))
            {
                System.IO.Directory.CreateDirectory(Path.GetDirectoryName(cacheFileName));
            }
            if (dnsdump)
            {
                DNSDump();
            }
            if (buildcacheonly)
            {
                GenerateCache();
            }
            if (certdump)
            {
                CertificateDump();
            }
            if (bhdump || autosplit)
            {
                ADDump();
            }
        }

        private void DNSDump()
        {
            List<ADObject> dnsobjects = ADWSUtils.GetObjects("dns");
            string outputFileName = outputDirectory + "DNS.txt";
            foreach (ADObject dnsobject in dnsobjects)
            {
                File.AppendAllText(outputFileName, "\r\n" + dnsobject.Name);
                hDNSRecord.ReadandOutputDNSObject(dnsobject.DnsRecord, outputFileName);
            }
            Console.WriteLine("-------------");
            Console.WriteLine("Output file generated in " + outputDirectory);
            dnsdump = false;
        }

        private void CertificateDump()
        {
            //Loading cache
            if (!File.Exists(cacheFileName))
            {
                Console.WriteLine("File: " + cacheFileName + " does not exist. Generate cache before executing this command.");
                return;
            }
            else
            {
                try
                {
                    Console.WriteLine("Loading cache from disk");
                    Cache.Deserialize(cacheFileName);
                    Console.WriteLine("Loaded cache with stats: " + Cache.GetCacheStats());
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error loading cache: {e}");
                    throw;
                }
            }

            //Generate cache of PKI objects 
            List<ADObject> cachedpkiobjects = ADWSUtils.GetObjects("pkicache");

            foreach (ADObject cachedpkiobject in cachedpkiobjects)
            {
                if (cachedpkiobject.CertificateTemplates != null)
                {
                    string caname = cachedpkiobject.Name.ToUpper();
                    foreach (string template in cachedpkiobject.CertificateTemplates)
                    {
                        PKICache.AddTemplateCA(template, caname);
                    }
                }
            }

            List<ADObject> adobjects = ADWSUtils.GetObjects("pkidata");
            OutputCA outputCA = new OutputCA();
            OutputCATemplate outputCATemplate = new OutputCATemplate();
            CAProcessor _ca = new CAProcessor();
            foreach (ADObject adobject in adobjects)
            {
                if (adobject.Class == "pkienrollmentservice")
                {
                    CA caNode = _ca.parseCA(adobject, domainName);
                    outputCA.data.Add(caNode);
                }

                if (adobject.Class == "pkicertificatetemplate")
                {
                    CATemplate caTemplate = _ca.parseCATemplate(adobject, domainName);
                    outputCATemplate.data.Add(caTemplate);
                }

            }
            outputCA.meta.count = outputCA.data.Count();
            outputCATemplate.meta.count = outputCATemplate.data.Count();
            var jsonString = JsonConvert.SerializeObject(outputCA);
            File.WriteAllText(outputDirectory + "CA.json", jsonString);
            //Console.WriteLine(jsonString);
            jsonString = JsonConvert.SerializeObject(outputCATemplate);
            File.WriteAllText(outputDirectory + "CATemplate.json", jsonString);
            Console.WriteLine("-------------");
            Console.WriteLine("Output files generated in " + outputDirectory);
            certdump = false;
        }

        private void ADDump()
        {
            //Loading cache
            if (!File.Exists(cacheFileName))
            {
                Console.WriteLine("File: " + cacheFileName + " does not exist. Generate cache before executing this command.");
                return;
            }
            else
            {
                try
                {
                    Console.WriteLine("Loading cache from disk");
                    Cache.Deserialize(cacheFileName);
                    Console.WriteLine("Loaded cache with stats: " + Cache.GetCacheStats());
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error loading cache: {e}");
                    throw;
                }
            }
            if (autosplit)
            {
                AutoSplit();
            }
            else
            {
                List<ADObject> adobjects = new List<ADObject>();
                adobjects = ADWSUtils.GetObjects("ad");
                CreateOutput(adobjects, "full");
                adobjects.Clear();
            }
        }

        private void GenerateCache()
        {
            if (string.IsNullOrEmpty(cacheFileName))
            {
                Console.WriteLine("Cache file name has not been defined.");
            }
            else
            {
                //Generate cache of all objects (SID,Type,CN)
                List<ADObject> cachedobjects = ADWSUtils.GetObjects("cache");

                foreach (ADObject cachedobject in cachedobjects)
                {
                    //parsing Computers,Users,Groups (ObjectSid != null)
                    if (cachedobject.ObjectSid != null)
                    {
                        string objectSid = cachedobject.ObjectSid.ToString();
                        //parsing WellKnownPrincipals
                        if (objectSid.StartsWith("S-1") && WellKnownPrincipal.GetWellKnownPrincipal(objectSid, out var commonPrincipal))
                        {
                            Cache.AddConvertedValue(cachedobject.DistinguishedName, objectSid);
                            Cache.AddType(objectSid, commonPrincipal.ObjectType);
                        }
                        else
                        {
                            Cache.AddConvertedValue(cachedobject.DistinguishedName, objectSid);
                            Cache.AddType(objectSid, ADWSUtils.ClasstoLabel(cachedobject.Class));
                        }
                    }
                    //parsing Domains,Containers,GPOs,OUs
                    else if (ADWSUtils.ClasstoLabel(cachedobject.Class) != Label.Base)
                    {
                        Cache.AddConvertedValue(cachedobject.DistinguishedName, cachedobject.ObjectGUID.ToString());
                        Cache.AddType(cachedobject.ObjectGUID.ToString(), ADWSUtils.ClasstoLabel(cachedobject.Class));
                    }
                }
                Cache.Serialize(cacheFileName);
            }
        }

        private void AutoSplit()
        {
            char firstChar;
            string dictKey = null;
            var dict = new Dictionary<string, int>();
            foreach (var key in Cache.ValueToIdCache.Keys)
            {
                if (key.StartsWith("CN="))
                {
                    firstChar = key.ToString().ToLower()[3];
                    if (!"abcdefghijklmnopqrstuvwxyz0123456789".Contains(firstChar))
                    {
                        dictKey = "nonchars";
                    }
                    else
                    {
                        dictKey = firstChar.ToString();
                    }
                }
                if (dictKey != null)
                {
                    if (dict.ContainsKey(dictKey))
                    {
                        dict[dictKey]++;
                    }
                    else
                    {
                        dict[dictKey] = 1;
                    }
                }

            }

            var sortedDict = new SortedDictionary<string, int>(dict);
            if (showStats)
            {
                foreach (var kvp in sortedDict)
                {
                    Console.WriteLine("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
                }
                Console.WriteLine("Finished");
                return;
            }

            //Gathering Domains data
            List<ADObject> domobjects = new List<ADObject>();
            domobjects = ADWSUtils.GetObjects("domains");
            CreateOutput(domobjects, "dom");
            domobjects.Clear();

            // Gathering non alphanumeric data
            if (sortedDict.ContainsKey("nonchars"))
            {
                List<ADObject> adobjects = new List<ADObject>();
                //ParseNonCharsADObjects();
                adobjects = ADWSUtils.GetObjects("nonchars");
                CreateOutput(adobjects, "nonchars");
                adobjects.Clear();
                sortedDict.Remove("nonchars");
            }

            sortedDict.Remove("nonchars");

            // Gathering autosplit data
            foreach (var item in sortedDict)
            {
                if (item.Value < threshold)
                {
                    Console.WriteLine("Gathering full letter: " + item.Key);
                    deep = false;
                    ParseAutosplitObjects(item.Key, c2);
                }
                else
                {
                    Console.WriteLine("Gathering split letter: " + item.Key);
                    deep = true;
                    ParseAutosplitObjects(item.Key, c2);
                }
            }
        }

        private void ParseAutosplitObjects(string str1, string str2)
        {
            foreach (char c1 in str1)
            {
                if (deep)
                {
                    //Gather 2nd depth level 
                    foreach (char c2 in str2)
                    {
                        List<ADObject> objects = ADWSUtils.GetObjects("(cn=" + c1 + c2 + "*)");
                        CreateOutput(objects, c1.ToString() + c2.ToString());
                        objects.Clear();
                    }
                    //Gather non alphanumeric in 2nd depth level
                    List<ADObject> adobjects = ADWSUtils.GetObjects("(&(cn=" + c1 + "*)(!(cn=" + c1 + "a*))(!(cn=" + c1 + "b*))(!(cn=" + c1 + "c*))(!(cn=" + c1 + "d*))(!(cn=" + c1 + "e*))(!(cn=" + c1 + "f*))(!(cn=" + c1 + "g*))(!(cn=" + c1 + "h*))(!(cn=" + c1 + "i*))(!(cn=" + c1 + "j*))(!(cn=" + c1 + "k*))(!(cn=" + c1 + "l*))(!(cn=" + c1 + "m*))(!(cn=" + c1 + "n*))(!(cn=" + c1 + "o*))(!(cn=" + c1 + "p*))(!(cn=" + c1 + "q*))(!(cn=" + c1 + "r*))(!(cn=" + c1 + "s*))(!(cn=" + c1 + "t*))(!(cn=" + c1 + "u*))(!(cn=" + c1 + "v*))(!(cn=" + c1 + "w*))(!(cn=" + c1 + "x*))(!(cn=" + c1 + "y*))(!(cn=" + c1 + "z*))(!(cn=" + c1 + "0*))(!(cn=" + c1 + "1*))(!(cn=" + c1 + "2*))(!(cn=" + c1 + "3*))(!(cn=" + c1 + "4*))(!(cn=" + c1 + "5*))(!(cn=" + c1 + "6*))(!(cn=" + c1 + "7*))(!(cn=" + c1 + "8*))(!(cn=" + c1 + "9*)))");
                    CreateOutput(adobjects, c1.ToString() + "_nonchars_");
                    adobjects.Clear();
                }
                else
                {
                    //Gather full letter
                    List<ADObject> adobjects = ADWSUtils.GetObjects("(cn=" + c1 + "*)");
                    CreateOutput(adobjects, c1.ToString());
                    adobjects.Clear();
                }
            }
        }

        public void CreateOutput(List<ADObject> adobjects, string header)
        {

            OutputComputers outputComputers = new OutputComputers();
            OutputUsers outputUsers = new OutputUsers();
            OutputGroups outputGroups = new OutputGroups();
            OutputDomains outputDomains = new OutputDomains();
            OutputGPOs outputGPOs = new OutputGPOs();
            OutputOUs outputOUs = new OutputOUs();
            OutputContainers outputContainers = new OutputContainers();

            foreach (ADObject adobject in adobjects)
            {
                if (adobject.Class == "computer")
                {
                    ComputerProcessor _comp = new ComputerProcessor();
                    ComputerNode computerNode = _comp.parseComputerObject(adobject, domainName);
                    outputComputers.data.Add(computerNode);
                }
                else if (adobject.Class == "user")
                {
                    UserProcessor _usr = new UserProcessor();
                    UserNode userNode = _usr.parseUserObject(adobject, domainName);
                    outputUsers.data.Add(userNode);
                }
                else if (adobject.Class == "group")
                {
                    GroupProcessor _grp = new GroupProcessor();
                    GroupNode groupNode = _grp.parseGroupObject(adobject, domainName);
                    outputGroups.data.Add(groupNode);

                }
                else if (adobject.Class == "domaindns" || adobject.Class == "domain")
                {
                    DomainProcessor _dom = new DomainProcessor(Server, Port, Credential);
                    DomainNode domainNode = _dom.parseDomainObject(adobject);
                    outputDomains.data.Add(domainNode);
                }
                else if (adobject.Class == "grouppolicycontainer")
                {
                    GPOProcessor _gpo = new GPOProcessor();
                    GPONode gpoNode = _gpo.parseGPOObject(adobject, domainName);
                    outputGPOs.data.Add(gpoNode);
                }
                else if (adobject.Class == "organizationalunit")
                {
                    OUProcessor _ou = new OUProcessor();
                    OUNode ouNode = _ou.parseOUObject(adobject, domainName);
                    outputOUs.data.Add(ouNode);
                }
                else if (adobject.Class == "container" || adobject.Class == "rpccontainer" || adobject.Class == "msimaging-psps" || adobject.Class == "msExchConfigurationContainer") //todo: add more custom container classes
                {
                    //filter out domainupdates and user/machine system policies
                    string dn = adobject.DistinguishedName.ToUpper();
                    if (dn.Contains("CN=DOMAINUPDATES,CN=SYSTEM"))
                        continue;
                    if (dn.Contains("CN=POLICIES,CN=SYSTEM") && (dn.StartsWith("CN=USER") || dn.StartsWith("CN=MACHINE")))
                        continue;

                    ContainerProcessor _cp = new ContainerProcessor();
                    ContainerNode containerNode = _cp.parseContainerObject(adobject, domainName);
                    outputContainers.data.Add(containerNode);
                }
                else
                {

                    //Trace.WriteLine("we have an unprocessed " + adobject.Class + " object:" + adobject.Name);
                }
            }
            outputUsers.meta.count = outputUsers.data.Count();
            if (outputUsers.meta.count > 0)
            {
                var jsonString = JsonConvert.SerializeObject(outputUsers);
                File.WriteAllText(outputDirectory + header + "_outputUsers.json", jsonString);
                //Console.WriteLine(jsonString);
            }

            outputComputers.meta.count = outputComputers.data.Count();
            if (outputComputers.meta.count > 0)
            {
                var jsonString = JsonConvert.SerializeObject(outputComputers);
                File.WriteAllText(outputDirectory + header + "_outputComputers.json", jsonString);
                //Console.WriteLine(jsonString);
            }

            outputGroups.meta.count = outputGroups.data.Count();
            if (outputGroups.meta.count > 0)
            {
                var jsonString = JsonConvert.SerializeObject(outputGroups);
                File.WriteAllText(outputDirectory + header + "_outputGroups.json", jsonString);
                //Console.WriteLine(jsonString);
            }

            outputDomains.meta.count = outputDomains.data.Count();
            if (outputDomains.meta.count > 0)
            {
                var jsonString = JsonConvert.SerializeObject(outputDomains);
                File.WriteAllText(outputDirectory + header + "_outputDomains.json", jsonString);
                //Console.WriteLine(jsonString);
            }

            outputGPOs.meta.count = outputGPOs.data.Count();
            if (outputGPOs.meta.count > 0)
            {
                var jsonString = JsonConvert.SerializeObject(outputGPOs);
                File.WriteAllText(outputDirectory + header + "_outputGPOs.json", jsonString);
                //Console.WriteLine(jsonString);
            }

            outputOUs.meta.count = outputOUs.data.Count();
            if (outputOUs.meta.count > 0)
            {
                var jsonString = JsonConvert.SerializeObject(outputOUs);
                File.WriteAllText(outputDirectory + header + "_outputOUs.json", jsonString);
                //Console.WriteLine(jsonString);
            }

            outputContainers.meta.count = outputContainers.data.Count();
            if (outputContainers.meta.count > 0)
            {
                var jsonString = JsonConvert.SerializeObject(outputContainers);
                File.WriteAllText(outputDirectory + header + "_outputContainers.json", jsonString);
                //Console.WriteLine(jsonString);
            }
            Console.WriteLine("-------------");
            Console.WriteLine("Output files with prefix \"" + header + "\" generated in " + outputDirectory);
            Console.WriteLine("-------------");

        }

    }

}

