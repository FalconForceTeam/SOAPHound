using SOAPHound.ADWS;
using SOAPHound.Enums;
using SOAPHound.OutputTypes;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace SOAPHound.Processors
{
    class GroupProcessor
    {
        public GroupNode parseGroupObject(ADObject adobject, string domainName)
        {
            DateTime EpochDiff = new DateTime(1970, 1, 1);
          
            // Extract domainsid from User SID
            string domainsid = adobject.ObjectSid.ToString().Substring(0, adobject.ObjectSid.ToString().LastIndexOf('-'));

            Label objectType = ADWSUtils.ResolveIDAndType(adobject.ObjectSid.ToString()).ObjectType;

            GroupNode adnode = new GroupNode()
            {

                ObjectIdentifier = adobject.ObjectSid.ToString(),
                Properties = new GroupProperties()
                {
                    name = adobject.SAMAccountName.ToUpper() + "@" + domainName.ToUpper(),
                    samaccountname = adobject.SAMAccountName,
                    domainsid = domainsid,
                    domain = domainName.ToUpper(),
                    distinguishedname = adobject.DistinguishedName,
                    whencreated = (long)adobject.WhenCreated.Subtract(EpochDiff).TotalSeconds,
                    description = adobject.Description,
                    admincount = (adobject.AdminCount > 0),
                    highvalue = IsHighValueGroup(adobject.ObjectSid.ToString()),
                },
                Members = parseMembers(adobject.Member),
                Aces = ACLProcessor.parseAces(adobject.NTSecurityDescriptor, objectType, false),
                IsDeleted = (adobject.IsDeleted == null) ? false : true,
                IsACLProtected = (adobject.NTSecurityDescriptor.AreAccessRulesProtected || adobject.NTSecurityDescriptor.AreAuditRulesProtected) ? true : false,
            };
            
            return adnode;

        }

        private TypedPrincipal[] parseMembers(string[] members)
        {
            TypedPrincipal[] Members = new TypedPrincipal[] { };
            if (members != null)
            {
                foreach (string member in members)
                {
                    TypedPrincipal Member = ADWSUtils.ResolveDistinguishedName(member);
                    Members = Members.Append(Member).ToArray();
                }
            }
            return Members;
        }

        private bool IsHighValueGroup(string objectId)
        {
            var suffixes = new string[]
            {
                "-512",
                "-516",
                "-519",
                "S-1-5-32-544",
                "S-1-5-32-548",
                "S-1-5-32-549",
                "S-1-5-32-550",
                "S-1-5-32-551",
            };
            foreach (var suffix in suffixes)
            {
                if (objectId.EndsWith(suffix))
                {
                    return true;
                }
            }
            return false;
        }

    }
}
