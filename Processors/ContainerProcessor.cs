using SOAPHound.ADWS;
using SOAPHound.Enums;
using SOAPHound.OutputTypes;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace SOAPHound.Processors
{
    class ContainerProcessor
    {
        public ContainerNode parseContainerObject(ADObject adobject, string domainName)
        {
            
            Label objectType = Label.Container;

            ContainerNode adnode = new ContainerNode()
            {

                ObjectIdentifier = adobject.ObjectGUID.ToString().ToUpper(),
                Properties = new ContainerProperties()
                {
                    name = adobject.Name.ToUpper() + "@" + domainName.ToUpper(),
                    domainsid = null,
                    domain = domainName.ToUpper(),
                    distinguishedname = adobject.DistinguishedName.ToUpper(),
                },
                ChildObjects = parseChildObjects(adobject.DistinguishedName),
                Aces = ACLProcessor.parseAces(adobject.NTSecurityDescriptor, objectType, false),
                IsDeleted = (adobject.IsDeleted == null) ? false : true,
                IsACLProtected = (adobject.NTSecurityDescriptor.AreAccessRulesProtected|| adobject.NTSecurityDescriptor.AreAuditRulesProtected) ? true : false,
            };
               
            return adnode;

        }

        private TypedPrincipal[] parseChildObjects(string dn)
        {
            Cache.GetChildObjects(dn, out TypedPrincipal[] childObjects);
            return childObjects;
        }





    }
}
