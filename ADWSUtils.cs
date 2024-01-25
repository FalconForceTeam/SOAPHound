using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SOAPHound.Enums;
using SOAPHound.ADWS;
using SOAPHound.Processors;
using SOAPHound.OutputTypes;
using System.Net;
using System.Text.RegularExpressions;
using System.Diagnostics;

namespace SOAPHound
{
    static class ADWSUtils
    {
        public static String Server { get; set; }
        public static int Port { get; set; }
        public static NetworkCredential Credential { get; set; }
        public static Boolean nolaps { get; set; }

        private static readonly Regex DCReplaceRegex = new Regex("DC=", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public static List<ADObject> GetObjects(string label)
        {
            string ldapquery = "";
            string[] properties = new string[] { };
            string banner = "";
            string ldapbase = "";

            switch (label)
            {
                case "dns":
                    banner = "Gathering DNS data";
                    ldapquery = "(&(ObjectClass=dnsNode))";
                    properties = new string[] { "Name", "dnsRecord" };
                    ldapbase = "CN=MicrosoftDNS,DC=DomainDnsZones,";
                    break;
                case "cache":
                    banner = "Generating cache";
                    ldapquery = "(!soaphound=*)";
                    properties = new string[] { "objectSid", "objectGUID", "distinguishedName" };
                    break;
                case "pkicache":
                    banner = "Gathering PKI cache";
                    ldapquery = "(!soaphound=*)";
                    properties = new string[] { "name", "certificateTemplates" };
                    ldapbase = "CN=Configuration,";
                    break;
                case "pkidata":
                    banner = "Gathering PKI data";
                    ldapquery = "(!soaphound=*)";
                    properties = new string[] { "name", "displayName", "nTSecurityDescriptor", "objectGUID", "dNSHostName", "nTSecurityDescriptor", "certificateTemplates", "cACertificate", "msPKI-Minimal-Key-Size", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-Private-Key-Flag", "pKIExtendedKeyUsage", "pKIOverlapPeriod", "pKIExpirationPeriod" };
                    ldapbase = "CN=Configuration,";
                    break;
                case "ad":
                    banner = "Gathering AD data";
                    ldapquery = "(!soaphound=*)";
                    if (nolaps)
                    {
                        properties = new string[] { "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID", "primaryGroupID", "distinguishedName", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "description", "operatingSystem", "sIDHistory", "nTSecurityDescriptor", "userAccountControl", "whenCreated", "lastLogon", "displayName", "title", "homeDirectory", "userPassword", "unixUserPassword", "scriptPath", "adminCount", "member", "msDS-Behavior-Version", "msDS-AllowedToDelegateTo", "gPCFileSysPath", "gPLink", "gPOptions" };
                    }
                    else
                    {
                        properties = new string[] { "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID", "primaryGroupID", "distinguishedName", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "description", "operatingSystem", "sIDHistory", "nTSecurityDescriptor", "userAccountControl", "whenCreated", "lastLogon", "ms-MCS-AdmPwdExpirationTime", "displayName", "title", "homeDirectory", "userPassword", "unixUserPassword", "scriptPath", "adminCount", "member", "msDS-Behavior-Version", "msDS-AllowedToDelegateTo", "gPCFileSysPath", "gPLink", "gPOptions" };

                    }
                    break;
                case "domaintrusts":
                    banner = "Gathering DomainTrusts data";
                    ldapquery = "(trustType=*)";
                    properties = new string[] { "trustAttributes", "trustDirection", "name", "securityIdentifier" };
                    break;
                case "domains":
                    banner = "Gathering Domains data";
                    ldapquery = "(ms-DS-MachineAccountQuota=*)";
                    properties = new string[] { "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID", "primaryGroupID", "distinguishedName", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "description", "operatingSystem", "sIDHistory", "nTSecurityDescriptor", "userAccountControl", "whenCreated", "lastLogon", "displayName", "title", "homeDirectory", "userPassword", "unixUserPassword", "scriptPath", "adminCount", "member", "msDS-Behavior-Version", "msDS-AllowedToDelegateTo", "gPCFileSysPath", "gPLink", "gPOptions" };
                    break;
                case "nonchars":
                    banner = "Gathering non alphanumeric objects";
                    ldapquery = "(&(cn=*)(!(cn=a*))(!(cn=b*))(!(cn=c*))(!(cn=d*))(!(cn=e*))(!(cn=f*))(!(cn=g*))(!(cn=h*))(!(cn=i*))(!(cn=j*))(!(cn=k*))(!(cn=l*))(!(cn=m*))(!(cn=n*))(!(cn=o*))(!(cn=p*))(!(cn=q*))(!(cn=r*))(!(cn=s*))(!(cn=t*))(!(cn=u*))(!(cn=v*))(!(cn=w*))(!(cn=x*))(!(cn=y*))(!(cn=z*))(!(cn=0*))(!(cn=1*))(!(cn=2*))(!(cn=3*))(!(cn=4*))(!(cn=5*))(!(cn=6*))(!(cn=7*))(!(cn=8*))(!(cn=9*)))";
                    if (nolaps)
                    {
                        properties = new string[] { "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID", "primaryGroupID", "distinguishedName", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "description", "operatingSystem", "sIDHistory", "nTSecurityDescriptor", "userAccountControl", "whenCreated", "lastLogon", "displayName", "title", "homeDirectory", "userPassword", "unixUserPassword", "scriptPath", "adminCount", "member", "msDS-Behavior-Version", "msDS-AllowedToDelegateTo", "gPCFileSysPath", "gPLink", "gPOptions" };
                    }
                    else
                    {
                        properties = new string[] { "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID", "primaryGroupID", "distinguishedName", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "description", "operatingSystem", "sIDHistory", "nTSecurityDescriptor", "userAccountControl", "whenCreated", "lastLogon", "ms-MCS-AdmPwdExpirationTime", "displayName", "title", "homeDirectory", "userPassword", "unixUserPassword", "scriptPath", "adminCount", "member", "msDS-Behavior-Version", "msDS-AllowedToDelegateTo", "gPCFileSysPath", "gPLink", "gPOptions" };

                    }
                    break;
                default:
                    banner = "Gathering autosplit data: " + label;
                    ldapquery = label;
                    if (nolaps)
                    {
                        properties = new string[] { "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID", "primaryGroupID", "distinguishedName", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "description", "operatingSystem", "sIDHistory", "nTSecurityDescriptor", "userAccountControl", "whenCreated", "lastLogon", "displayName", "title", "homeDirectory", "userPassword", "unixUserPassword", "scriptPath", "adminCount", "member", "msDS-Behavior-Version", "msDS-AllowedToDelegateTo", "gPCFileSysPath", "gPLink", "gPOptions" };
                    }
                    else
                    {
                        properties = new string[] { "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID", "primaryGroupID", "distinguishedName", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "description", "operatingSystem", "sIDHistory", "nTSecurityDescriptor", "userAccountControl", "whenCreated", "lastLogon", "ms-MCS-AdmPwdExpirationTime", "displayName", "title", "homeDirectory", "userPassword", "unixUserPassword", "scriptPath", "adminCount", "member", "msDS-Behavior-Version", "msDS-AllowedToDelegateTo", "gPCFileSysPath", "gPLink", "gPOptions" };

                    }
                    break;
            }
            Console.WriteLine("-------------");
            Console.WriteLine(banner);
            var AWDSConnection = new ADWSConnector(Server, Credential);
            ADInfo domainInfo = AWDSConnection.GetADInfo();

            string domainName = domainInfo.DomainName;
            ldapbase += domainInfo.DefaultNamingContext;
            List<ADObject> adobjects = AWDSConnection.Enumerate(ldapbase, ldapquery, new List<string>(properties));

            Console.WriteLine("ADWS request with ldapbase (" + ldapbase + "), ldapquery: " + ldapquery + " and ldapproperties: " + "[{0}]", string.Join(", ", properties));
            Console.WriteLine(banner + " complete");
            return adobjects;
        }

        public static TypedPrincipal ResolveIDAndType(string id)
        {
            //This is a duplicated SID object which is weird and makes things unhappy. Throw it out
            if (id.Contains("0ACNF"))
                return null;

            if (WellKnownPrincipal.GetWellKnownPrincipal(id, out var principal))
                return principal;

            var type = LookupSidType(id);
            return new TypedPrincipal(id, type);
        }

        public static Label LookupSidType(string sid)
        {
            if (Cache.GetIDType(sid, out var type))
                return type;
            else
                return Label.Base;

        }

        public static Label ClasstoLabel(string Class)
        {
            if (Class == "group")
                return Label.Group;

            if (Class == "user" || Class == "msds-managedserviceaccount" || Class == "msds-groupmanagedserviceaccount")
                return Label.User;

            if (Class == "computer")
                return Label.Computer;

            if (Class == "grouppolicycontainer")
                return Label.GPO;

            if (Class == "container")
                return Label.Container;

            if (Class == "organizationalunit")
                return Label.OU;

            if (Class == "domain" || Class == "domaindns" || Class == "trusteddomain")
                return Label.Domain;

            return Label.Base;
        }

        public static TypedPrincipal ResolveDistinguishedName(string dn)
        {
            if (Cache.GetConvertedValue(dn, out var id) && Cache.GetIDType(id, out var type))
                return new TypedPrincipal
                {
                    ObjectIdentifier = id,
                    ObjectType = type
                };
            else
                return new TypedPrincipal
                {
                    ObjectIdentifier = null,
                    ObjectType = Label.Base
                };
        }

        public static string DistinguishedNameToDomain(string distinguishedName)
        {
            var idx = distinguishedName.IndexOf("DC=",
                StringComparison.CurrentCultureIgnoreCase);
            if (idx < 0)
                return null;

            var temp = distinguishedName.Substring(idx);
            temp = DCReplaceRegex.Replace(temp, "").Replace(",", ".").ToUpper();
            return temp;
        }
    }
}
