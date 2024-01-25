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
    class OUProcessor
    {
        public OUNode parseOUObject(ADObject adobject, string domainName)
        {
            DateTime EpochDiff = new DateTime(1970, 1, 1);

            Label objectType = Label.OU;

            OUNode adnode = new OUNode()
            {

                ObjectIdentifier = adobject.ObjectGUID.ToString().ToUpper(),
                Properties = new OUProperties()
                {
                    name = adobject.Name.ToUpper() + "@" + domainName.ToUpper(),
                    domainsid = null,
                    domain = domainName.ToUpper(),
                    distinguishedname = adobject.DistinguishedName.ToUpper(),
                    whencreated = (long)adobject.WhenCreated.Subtract(EpochDiff).TotalSeconds,
                    description = adobject.Description,
                    blocksinheritance = (adobject.GPOptions == 1)?true:false,
                },
                Links = parseLinks(adobject.GPLink),
                ChildObjects = parseChildObjects(adobject.DistinguishedName),
                Aces = ACLProcessor.parseAces(adobject.NTSecurityDescriptor, objectType, false),
                IsDeleted = (adobject.IsDeleted == null) ? false : true,
                IsACLProtected = (adobject.NTSecurityDescriptor.AreAccessRulesProtected || adobject.NTSecurityDescriptor.AreAuditRulesProtected) ? true : false,
            };
            
            return adnode;

        }

        private GPLink[] parseLinks(string gplink)
        {
            GPLink[] links = new GPLink[] { };
            if (!gplink.ToUpper().Contains("CN"))
            {
                return links; // return empty if gplink is invalid
            }
            string[] splitlinks = gplink.Split(new string[] { "[", "]" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string splitlink in splitlinks)
            {
                string enforceValue = splitlink.Split(';')[1];
                string gpo = splitlink.Split(';')[0].Remove(0,7);
                if (Cache.GetConvertedValue(gpo, out var guid))
                {
                    GPLink link = new GPLink();
                    if (enforceValue == "2")
                    {
                        link.IsEnforced = true;
                    }
                    else
                    {
                        link.IsEnforced = false;
                    }
                    link.GUID = guid.ToUpper();
                    links = links.Append(link).ToArray();
                }
                else 
                {
                    Trace.WriteLine("GPO with dn " + gpo + " not found in cache.");
                    continue;
                }

            }
            return links;
        }

        private TypedPrincipal[] parseChildObjects(string dn)
        {
            Cache.GetChildObjects(dn, out TypedPrincipal[] childObjects);
            return childObjects;
        }

 



    }
}
