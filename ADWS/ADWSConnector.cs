using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Xml.Serialization;
using System.Xml;
using System.Xml.Linq;
using System.ServiceModel.Description;
using System.Globalization;
using System.Security.Principal;
using System.DirectoryServices;
using System;
using System.Linq;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace SOAPHound.ADWS
{
    internal class ADWSConnector
    {
        string BaseUri { get; set; }
        NetworkCredential Credentials { get; set; }

        NetTcpBinding Binding { get; set; }
        MessageVersion Version { get; set; }
        public ADWSConnector(string Host, NetworkCredential Credentials)
        {
            UriBuilder uriBuilder = new UriBuilder();
            uriBuilder.Scheme = "net.tcp";
            uriBuilder.Host = Host;
            uriBuilder.Port = 9389;
            this.BaseUri = uriBuilder.ToString();

            this.Binding = new NetTcpBinding();

            this.Binding.OpenTimeout = new TimeSpan(0, 10, 0);
            this.Binding.CloseTimeout = new TimeSpan(0, 10, 0);
            this.Binding.SendTimeout = new TimeSpan(0, 10, 0);
            this.Binding.ReceiveTimeout = new TimeSpan(0, 10, 0);
            this.Binding.MaxBufferSize = 1073741824;
            this.Binding.MaxReceivedMessageSize = 1073741824;
            this.Binding.ReaderQuotas.MaxDepth = 64;
            this.Binding.ReaderQuotas.MaxArrayLength = 2147483647;
            this.Binding.ReaderQuotas.MaxStringContentLength = 2147483647;
            this.Binding.ReaderQuotas.MaxNameTableCharCount = 2147483647;
            this.Binding.ReaderQuotas.MaxBytesPerRead = 2147483647;
            EnvelopeVersion envelopeVersion = EnvelopeVersion.Soap12;
            AddressingVersion addressingVersion = AddressingVersion.WSAddressing10;
            this.Version = MessageVersion.CreateVersion(envelopeVersion, addressingVersion);
            this.Credentials = Credentials;
        }

        static XmlReader XmlReaderFromString(string xml)
        {
            return XmlReader.Create(new StringReader(xml));
        }

        static XDocument MessageToXDocument(Message message)
        {
            return XDocument.Parse(ReplaceHexadecimalSymbols(message.ToString()));
        }

        static string ReplaceHexadecimalSymbols(string txt)
        {
            string r = "[\x00-\x08\x0B\x0C\x0E-\x1F\x26]";
            return Regex.Replace(txt, r, "", RegexOptions.Compiled);
        }

        public EndpointAddress GetEndpointAddress(string path)
        {
            return new EndpointAddress(this.BaseUri + path);
        }

        public void UpdateCredentials(ClientCredentials c)
        {
            c.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Impersonation;
            c.Windows.ClientCredential = this.Credentials;
        }

        public static string ConvertLdapNamingContextToDomain(string ldapContext)
        {
            if (string.IsNullOrEmpty(ldapContext))
            {
                return string.Empty;
            }
            var components = ldapContext.Split(',');
            var domainComponents = components.Select(c => c.Replace("DC=", "")).ToArray();
            return string.Join(".", domainComponents);
        }

        public ADInfo GetADInfo()
        {
            ADInfo adInfo = new ADInfo();
            var endpointAddress = GetEndpointAddress("ActiveDirectoryWebServices/Windows/Resource");

            var resourceClient = new ADWS.ResourceClient(this.Binding, endpointAddress);
            UpdateCredentials(resourceClient.ClientCredentials);

            var rcRequest = Message.CreateMessage(Version, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get");
            MessageHeader hdr = MessageHeader.CreateHeader("instance", "http://schemas.microsoft.com/2008/1/ActiveDirectory", "ldap:389");
            MessageHeader hdr2 = MessageHeader.CreateHeader("objectReferenceProperty", "http://schemas.microsoft.com/2008/1/ActiveDirectory", "11111111-1111-1111-1111-111111111111");

            rcRequest.Headers.Add(hdr);
            rcRequest.Headers.Add(hdr2);

            Message resp = resourceClient.GetAsync(rcRequest).Result;
            var getResponse = MessageToXDocument(resp);
            string defaultNamingContext = getResponse
                .Descendants(XName.Get("defaultNamingContext", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"))
                .Descendants(XName.Get("value", "http://schemas.microsoft.com/2008/1/ActiveDirectory"))
                .FirstOrDefault()
                .Value;

            adInfo.DefaultNamingContext = defaultNamingContext;
            adInfo.DomainName = ConvertLdapNamingContextToDomain(defaultNamingContext);

            return adInfo;
        }

        public List<ADObject> Enumerate(string ldapBase, string ldapFilter, List<string> properties, int batchSize = 1000)
        {
            List<ADObject> list = new List<ADObject>();
            var endpointAddress = new System.ServiceModel.EndpointAddress(this.BaseUri + "ActiveDirectoryWebServices/Windows/Enumeration");

            var searchClient = new ADWS.SearchClient(this.Binding, endpointAddress);
            UpdateCredentials(searchClient.ClientCredentials);

            var enumerateRequest = new EnumerateRequest
            {
                Filter = new EnumerateRequestFilter
                {
                    LdapQuery = new LdapQuery
                    {
                        QueryFilter = ldapFilter,
                        BaseObject = ldapBase,
                        Scope = "Subtree"
                    }
                },
                Selection = new EnumerateRequestSelection
                {
                    SelectionProperties = properties.Select(s => "d:" + s).ToList()
                }
            };

            var Request = Message.CreateMessage(Version, "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", XmlReaderFromString(ObjectToXml(enumerateRequest)));
            MessageHeader hdr = MessageHeader.CreateHeader("instance", "http://schemas.microsoft.com/2008/1/ActiveDirectory", "ldap:389");

            Request.Headers.Add(hdr);

            Message resp = searchClient.EnumerateAsync(Request).Result;

            var enumerateResponse = MessageToXDocument(resp);
            string enumerationContext = enumerateResponse
                .Descendants(XName.Get("EnumerationContext", "http://schemas.xmlsoap.org/ws/2004/09/enumeration"))
                .FirstOrDefault()?
                .Value;
            if (enumerationContext == null)
            {
                throw new Exception("EnumerationContext could not be extracted from Enumerate response. This could be because your domain does not use LAPS and you are running without the --nolaps option.");
            }

            var pullRequest = new PullSearchResultsRequest
            {
                EnumerationContext = enumerationContext,
                MaxElements = batchSize,
                Controls = new Controls
                {
                    Control = new List<Control>
                    {
                        new Control
                        {
                            Type = "1.2.840.113556.1.4.801",
                            ControlValue = "MIQAAAADAgEH"
                        }
                    }
                }
            };

            var adObjects = new List<ADObject>();
            bool endOfSequence = false;
            while (!endOfSequence)
            {

                var pullRequestMessage = Message.CreateMessage(Version, "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull", XmlReaderFromString(ObjectToXml(pullRequest)));

                pullRequestMessage.Headers.Add(hdr);
                Message resp2 = searchClient.PullAsync(pullRequestMessage).Result;
                var pullResponse = MessageToXDocument(resp2);
                adObjects.AddRange(ExtractADObjectsFromResponse(pullResponse));
                endOfSequence = pullResponse
                    .Descendants(XName.Get("EndOfSequence", "http://schemas.xmlsoap.org/ws/2004/09/enumeration"))
                    .Count() > 0;
            }
            return adObjects;
        }
        private static ActiveDirectorySecurity ParseActiveDirectorySecurity(string value)
        {
            byte[] data = Convert.FromBase64String(value);
            ActiveDirectorySecurity sd = new ActiveDirectorySecurity();
            sd.SetSecurityDescriptorBinaryForm(data);
            return sd;
        }

        private static X509Certificate2Collection ParseX509Certificate2Collection(string[] propertyValues)
        {
            X509Certificate2Collection collection = new X509Certificate2Collection();
            if (propertyValues == null)
            {
                return collection;
            }
            foreach (var propertyValue in propertyValues)
            {
                try
                {
                    byte[] data = Convert.FromBase64String(propertyValue);
                    collection.Add(new X509Certificate2(data));
                }
                catch (Exception)
                {

                }
            }
            return collection;
        }

        private static SecurityIdentifier[] ParseSecurityIdentifierList(string[] propertyValues)
        {
            List<SecurityIdentifier> collection = new List<SecurityIdentifier>();
            if (propertyValues == null)
            {
                return collection.ToArray();
            }
            foreach (var propertyValue in propertyValues)
            {
                try
                {
                    byte[] data = Convert.FromBase64String(propertyValue);
                    collection.Add(new SecurityIdentifier(data, 0));
                }
                catch (Exception)
                {

                }
            }
            return collection.ToArray();
        }
        private static List<ADObject> ExtractADObjectsFromResponse(XDocument pullResponse)
        {
            XNamespace addata = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data";
            XNamespace ad = "http://schemas.microsoft.com/2008/1/ActiveDirectory";
            XNamespace wsen = "http://schemas.xmlsoap.org/ws/2004/09/enumeration";


            var entries = new List<Dictionary<string, string>>();
            var arrayKeys = new List<string> { "member", "msDS-AllowedToDelegateTo", "pKIExtendedKeyUsage", "servicePrincipalName", "certificateTemplates", "cACertificate", "sIDHistory" };

            var adObjects = new List<ADObject> { };

            foreach (var element in pullResponse.Descendants(wsen + "Items").Elements())
            {
                var adobject = new ADObject();
                adobject.Class = element.Name.LocalName.ToLowerInvariant();
                foreach (var property in element.Elements())
                {
                    var propertyName = property.Name.LocalName;
                    var propertyValue = property.Element(ad + "value").Value;
                    string[] propertyValues = null;
                    if (arrayKeys.Contains(propertyName))
                    {
                        propertyValues = property.Elements(ad + "value").Select(v => v.Value).ToArray();
                    }
                    switch (propertyName)
                    {
                        case "class":
                            adobject.Class = propertyValue;
                            break;
                        case "adminCount":
                            adobject.AdminCount = int.Parse(propertyValue);
                            break;
                        case "cACertificate":
                            adobject.CACertificate = ParseX509Certificate2Collection(propertyValues);
                            break;
                        case "certificateTemplates":
                            adobject.CertificateTemplates = propertyValues;
                            break;
                        case "description":
                            adobject.Description = propertyValue;
                            break;
                        case "displayName":
                            adobject.DisplayName = propertyValue;
                            break;
                        case "distinguishedName":
                            adobject.DistinguishedName = propertyValue;
                            break;
                        case "dNSHostName":
                            adobject.DNSHostName = propertyValue;
                            break;
                        case "cn":
                            adobject.Cn = propertyValue;
                            break;
                        case "dnsRecord":
                            adobject.DnsRecord = Convert.FromBase64String(propertyValue);
                            break;
                        case "ms-DS-MachineAccountQuota":
                            adobject.DSMachineAccountQuota = int.Parse(propertyValue);
                            break;
                        case "gPCFileSysPath":
                            adobject.GPCFileSysPath = propertyValue;
                            break;
                        case "isDeleted":
                            adobject.IsDeleted = propertyValue;
                            break;
                        case "gPLink":
                            adobject.GPLink = propertyValue;
                            break;
                        case "gPOptions":
                            adobject.GPOptions = int.Parse(propertyValue);
                            break;
                        case "lastLogon":
                            adobject.LastLogon = FromLongToDateTime(long.Parse(propertyValue));
                            break;
                        case "lastLogonTimestamp":
                            adobject.LastLogonTimestamp = FromLongToDateTime(long.Parse(propertyValue));
                            break;
                        case "member":
                            adobject.Member = propertyValues;
                            break;
                        case "msDS-AllowedToActOnBehalfOfOtherIdentity":
                            adobject.MsDSAllowedToActOnBehalfOfOtherIdentity = ParseActiveDirectorySecurity(propertyValue);
                            break;
                        case "msDS-AllowedToDelegateTo":
                            adobject.MsDSAllowedToDelegateTo = propertyValues;
                            break;
                        case "msDS-Behavior-Version":
                            adobject.FunctionalLevel = int.Parse(propertyValue);
                            break;
                        case "ms-Mcs-AdmPwdExpirationTime":
                            adobject.MsMCSAdmPwdExpirationTime = long.Parse(propertyValue);
                            break;
                        case "msPKI-Certificate-Name-Flag":
                            adobject.MsPKICertificateNameFlag = int.Parse(propertyValue);
                            break;
                        case "msPKI-Minimal-Key-Size":
                            adobject.MsPKIMinimalKeySize = int.Parse(propertyValue);
                            break;
                        case "msPKI-Enrollment-Flag":
                            adobject.MsPKIEnrollmentFlag = int.Parse(propertyValue);
                            break;
                        case "msPKI-Private-Key-Flag":
                            adobject.MsPKIPrivateKeyFlag = int.Parse(propertyValue);
                            break;
                        case "name":
                            adobject.Name = propertyValue;
                            break;
                        case "nTSecurityDescriptor":
                            adobject.NTSecurityDescriptor = ParseActiveDirectorySecurity(propertyValue);
                            break;
                        case "objectGUID":
                            adobject.ObjectGUID = new Guid(Convert.FromBase64String(propertyValue));
                            break;
                        case "objectSid":
                            adobject.ObjectSid = new SecurityIdentifier(Convert.FromBase64String(propertyValue), 0);
                            break;
                        case "operatingSystem":
                            adobject.OperatingSystem = propertyValue;
                            break;
                        case "pKIExtendedKeyUsage":
                            adobject.PKIExtendedKeyUsage = propertyValues;
                            break;
                        case "primaryGroupID":
                            adobject.PrimaryGroupID = int.Parse(propertyValue);
                            break;
                        case "pwdLastSet":
                            adobject.PwdLastSet = FromLongToDateTime(long.Parse(propertyValue));
                            break;
                        case "sAMAccountName":
                            adobject.SAMAccountName = propertyValue;
                            break;
                        case "scriptPath":
                            adobject.ScriptPath = propertyValue;
                            break;
                        case "securityIdentifier":
                            adobject.SecurityIdentifier = new SecurityIdentifier(Convert.FromBase64String(propertyValue), 0);
                            break;
                        case "servicePrincipalName":
                            adobject.ServicePrincipalName = propertyValues;
                            break;
                        case "sIDHistory":
                            adobject.SIDHistory = ParseSecurityIdentifierList(propertyValues);
                            break;
                        case "trustAttributes":
                            adobject.TrustAttributes = int.Parse(propertyValue);
                            break;
                        case "trustDirection":
                            adobject.TrustDirection = int.Parse(propertyValue);
                            break;
                        case "userAccountControl":
                            adobject.UserAccountControl = int.Parse(propertyValue);
                            break;
                        case "whenCreated":
                            adobject.WhenCreated = DateTime.ParseExact(propertyValue, "yyyyMMddHHmmss.f'Z'", CultureInfo.InvariantCulture);
                            break;
                        case "mail":
                            adobject.Email = propertyValue;
                            break;
                        case "title":
                            adobject.Title = propertyValue;
                            break;
                        case "homeDirectory":
                            adobject.HomeDirectory = propertyValue;
                            break;
                        case "userPassword":
                            adobject.UserPassword = propertyValue;
                            break;
                        case "unixUserPassword":
                            adobject.UnixUserPassword = propertyValue;
                            break;
                        case "unicodePassword":
                            adobject.UnicodePassword = propertyValue;
                            break;
                        case "msSFU30Password":
                            adobject.MsSFU30Password = propertyValue;
                            break;
                        case "pKIExpirationPeriod":
                            adobject.PKIExpirationPeriod = Convert.FromBase64String(propertyValue);
                            break;
                        case "pKIOverlapPeriod":
                            adobject.PKIOverlapPeriod = Convert.FromBase64String(propertyValue);
                            break;
                        default:
                            break;
                    }
                }
                adObjects.Add(adobject);
            }
            return adObjects;
        }

        private static string ObjectToXml<T>(T enumerate)
        {
            string XmlData;
            var serializer = new XmlSerializer(typeof(T));
            using (var writer = new StringWriter())
            {
                using (var xmlWriter = XmlWriter.Create(writer, new XmlWriterSettings { Indent = true, OmitXmlDeclaration = true }))
                {
                    var namespaces = new XmlSerializerNamespaces();
                    namespaces.Add("d", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data");
                    serializer.Serialize(xmlWriter, enumerate, namespaces);
                    XmlData = writer.ToString();
                }
            }

            return XmlData;
        }

        private static DateTime FromLongToDateTime(long value)
        {
            try
            {
                return DateTime.FromFileTime(value);
            }
            catch
            {
                return DateTime.MinValue;
            }
        }
    }

    public class ADInfo
    {
        public string DefaultNamingContext { get; set; }
        public string DomainName { get; set; }
    }

    [XmlRoot("Enumerate", Namespace = "http://schemas.xmlsoap.org/ws/2004/09/enumeration")]
    public class EnumerateRequest
    {
        [XmlElement("Filter")]
        public EnumerateRequestFilter Filter { get; set; }

        [XmlElement("Selection", Namespace = "http://schemas.microsoft.com/2008/1/ActiveDirectory")]
        public EnumerateRequestSelection Selection { get; set; }
    }

    public class EnumerateRequestFilter
    {
        [XmlAttribute("Dialect")]
        public string Dialect { get; set; }

        [XmlElement("LdapQuery", Namespace = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery")]
        public LdapQuery LdapQuery { get; set; }

        public EnumerateRequestFilter()
        {
            Dialect = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery";
        }
    }

    public class LdapQuery
    {
        [XmlElement("Filter")]
        public string QueryFilter { get; set; }

        [XmlElement("BaseObject")]
        public string BaseObject { get; set; }

        [XmlElement("Scope")]
        public string Scope { get; set; }
    }

    public class EnumerateRequestSelection
    {
        [XmlAttribute("Dialect")]
        public string Dialect { get; set; }

        [XmlElement("SelectionProperty")]
        public List<string> SelectionProperties { get; set; }

        public EnumerateRequestSelection()
        {
            Dialect = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1";
            SelectionProperties = new List<string>();
        }
    }

    [XmlRoot(ElementName = "Pull", Namespace = "http://schemas.xmlsoap.org/ws/2004/09/enumeration")]
    public class PullSearchResultsRequest
    {
        [XmlElement(ElementName = "EnumerationContext")]
        public string EnumerationContext { get; set; }

        [XmlElement(ElementName = "MaxElements")]
        public int MaxElements { get; set; }

        [XmlElement(ElementName = "controls", Namespace = "http://schemas.microsoft.com/2008/1/ActiveDirectory")]
        public Controls Controls { get; set; }
    }

    public class Controls
    {
        [XmlElement(ElementName = "control")]
        public List<Control> Control { get; set; }
    }

    public class Control
    {
        [XmlAttribute(AttributeName = "type")]
        public string Type { get; set; }

        [XmlElement(ElementName = "controlValue")]
        public string ControlValue { get; set; }
    }



}
