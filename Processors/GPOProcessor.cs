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
    class GPOProcessor
    {
        public GPONode parseGPOObject(ADObject adobject, string domainName)
        {
            DateTime EpochDiff = new DateTime(1970, 1, 1);

            Label objectType = Label.GPO;
            GPONode adnode = new GPONode()
            {

                ObjectIdentifier = adobject.ObjectGUID.ToString().ToUpper(),
                Properties = new GPOProperties()
                {
                    name = adobject.DisplayName.ToUpper() + "@" + domainName.ToUpper(),
                    domainsid = "null",
                    domain = domainName.ToUpper(),
                    distinguishedname = adobject.DistinguishedName.ToUpper(),
                    whencreated = (long)adobject.WhenCreated.Subtract(EpochDiff).TotalSeconds,
                    description = adobject.Description,
                    gpcpath = adobject.GPCFileSysPath.ToUpper(),
                },
                Aces = ACLProcessor.parseAces(adobject.NTSecurityDescriptor, objectType, false),
                IsDeleted = (adobject.IsDeleted == null) ? false : true,
                IsACLProtected = (adobject.NTSecurityDescriptor.AreAccessRulesProtected || adobject.NTSecurityDescriptor.AreAuditRulesProtected) ? true : false,
            };
            
            return adnode;

        }

    }
}
