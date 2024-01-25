using SOAPHound.ADWS;
using SOAPHound.Enums;
using SOAPHound.OutputTypes;
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace SOAPHound.Processors
{
    class DomainProcessor
    {
        private string Server = null;
        private int Port = 9389;
        private NetworkCredential Credential = null;

        public DomainProcessor(string argServer, int argPort, NetworkCredential argCredential)
        {
            Server = argServer;
            Port = argPort;
            Credential = argCredential;
        }
        public DomainNode parseDomainObject(ADObject adobject)
        {
            DateTime EpochDiff = new DateTime(1970, 1, 1);
            
            Label objectType = ADWSUtils.ResolveIDAndType(adobject.ObjectSid.ToString()).ObjectType;
            var trustedDomains = ADWSUtils.GetObjects("domaintrusts");

            DomainNode adnode = new DomainNode()
            {

                ObjectIdentifier = adobject.ObjectSid.ToString(),
                Properties = new DomainProperties()
                {
                    name = ADWSUtils.DistinguishedNameToDomain(adobject.DistinguishedName).ToUpper(),
                    domainsid = adobject.ObjectSid.ToString(),
                    domain = ADWSUtils.DistinguishedNameToDomain(adobject.DistinguishedName),
                    distinguishedname = adobject.DistinguishedName.ToUpper(),
                    description = adobject.Description,
                    functionallevel = FunctionalLevelToString(adobject.FunctionalLevel),
                    whencreated = (long)adobject.WhenCreated.Subtract(EpochDiff).TotalSeconds,
                    highvalue = true,
                },
                Aces = ACLProcessor.parseAces(adobject.NTSecurityDescriptor, objectType, false),
                Links = { },
                ChildObjects = parseChildObjects(adobject.DistinguishedName),
                GPOChanges = { },
                IsDeleted = (adobject.IsDeleted == null) ? false : true,
                IsACLProtected = (adobject.NTSecurityDescriptor.AreAccessRulesProtected || adobject.NTSecurityDescriptor.AreAuditRulesProtected) ? true : false,
            };
            foreach (ADObject trustedDomain in trustedDomains)
            {
                DomainTrustProcessor _dtp = new DomainTrustProcessor();
                DomainTrust trust = _dtp.ProcessDomainTrusts(trustedDomain);
                adnode.Trusts = adnode.Trusts.Append(trust).ToArray();
            }
            return adnode;

        }

        public static string FunctionalLevelToString(int level)
        {
            string functionalLevel;
            switch (level)
            {
                case 0:
                    functionalLevel = "2000 Mixed/Native";
                    break;
                case 1:
                    functionalLevel = "2003 Interim";
                    break;
                case 2:
                    functionalLevel = "2003";
                    break;
                case 3:
                    functionalLevel = "2008";
                    break;
                case 4:
                    functionalLevel = "2008 R2";
                    break;
                case 5:
                    functionalLevel = "2012";
                    break;
                case 6:
                    functionalLevel = "2012 R2";
                    break;
                case 7:
                    functionalLevel = "2016";
                    break;
                default:
                    functionalLevel = "Unknown";
                    break;
            }

            return functionalLevel;
        }

        private TypedPrincipal[] parseChildObjects(string dn)
        {
            Cache.GetDomainChildObjects(dn, out TypedPrincipal[] childObjects);
            return childObjects;
        }
    }
}
