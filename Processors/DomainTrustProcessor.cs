using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using SOAPHound.ADWS;
using SOAPHound.Enums;
using SOAPHound.OutputTypes;

namespace SOAPHound.Processors
{
    public class DomainTrustProcessor
    {
        public DomainTrust ProcessDomainTrusts(ADObject adobject)
        {

            var trust = new DomainTrust();
            if (adobject.SecurityIdentifier != null)
            { 
                trust.TargetDomainSid = adobject.SecurityIdentifier.ToString();
                trust.TrustDirection = Convert.ToInt32((TrustDirection)adobject.TrustDirection);
                TrustAttributes attributes = (TrustAttributes)adobject.TrustAttributes;
                trust.IsTransitive = (attributes & TrustAttributes.NonTransitive) == 0;
                trust.TargetDomainName = adobject.Name.ToUpper();
                trust.SidFilteringEnabled = (attributes & TrustAttributes.FilterSids) != 0;
                trust.TrustType = Convert.ToInt32((TrustAttributesToType(attributes)));
            }
            return trust;
        }

        public static TrustType TrustAttributesToType(TrustAttributes attributes)
        {
            TrustType trustType;

            if ((attributes & TrustAttributes.WithinForest) != 0)
                trustType = TrustType.ParentChild;
            else if ((attributes & TrustAttributes.ForestTransitive) != 0)
                trustType = TrustType.Forest;
            else if ((attributes & TrustAttributes.TreatAsExternal) != 0 ||
                     (attributes & TrustAttributes.CrossOrganization) != 0)
                trustType = TrustType.External;
            else
                trustType = TrustType.Unknown;

            return trustType;
        }
    }
}