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
    class ComputerProcessor
    {
        public ComputerNode parseComputerObject(ADObject adobject, string domainName)
        {
            DateTime EpochDiff = new DateTime(1970, 1, 1);
            bool enabled, unconstrained, trustedToAuth, hasLaps;

            // Extract domainsid from Computer SID
            string domainsid = adobject.ObjectSid.ToString().Substring(0, adobject.ObjectSid.ToString().LastIndexOf('-'));

            //checking if SIDHistory is not null, then convert SecurityIdentifier[] to String[] withn LINQ (triggers exception if null)
            string[] sidhistorytmp = new string[] { };
            if (adobject.SIDHistory != null)
            {
                sidhistorytmp = adobject.SIDHistory.Select(i => i.ToString()).ToArray(); // TO BE TESTED
            }
            else
                sidhistorytmp = new string[] { };


            var uac = adobject.UserAccountControl.ToString();

            if (int.TryParse(uac, out var flag))
            {
                var flags = (UacFlags)flag;
                enabled = (flags & UacFlags.AccountDisable) == 0;
                unconstrained = (flags & UacFlags.TrustedForDelegation) == UacFlags.TrustedForDelegation;
                trustedToAuth = (flags & UacFlags.TrustedToAuthForDelegation) != 0;
            }
            else
            {
                unconstrained = false;
                enabled = true;
                trustedToAuth = false;
            }

    


            if (adobject.MsMCSAdmPwdExpirationTime != 0)
            {
                hasLaps = true;
            }
            else
                hasLaps = false;


            //TODO allowedtodelegate

            var allowedToActPrincipals = new List<TypedPrincipal>();
            ActiveDirectorySecurity sd = adobject.MsDSAllowedToActOnBehalfOfOtherIdentity;
            if (sd != null)
            {
                foreach (ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    var res = new TypedPrincipal();
                    res.ObjectIdentifier = rule.IdentityReference.ToString();
                    res.ObjectType = ADWSUtils.ResolveIDAndType(res.ObjectIdentifier).ObjectType;
                    allowedToActPrincipals.Add(res);
                }
            }
            Label objectType = ADWSUtils.ResolveIDAndType(adobject.ObjectSid.ToString()).ObjectType;

            string compName = "UNKNOWN";
            var shortName = adobject.SAMAccountName?.TrimEnd('$');
            var dns = adobject.DNSHostName;
            var cn = adobject.Cn;
            var itemDomain = domainName.ToUpper();

            if (dns != null)
                compName = dns;
            else if (shortName == null && cn == null)
                compName = $"UNKNOWN.{itemDomain}";
            else if (shortName != null)
                compName = $"{shortName}.{itemDomain}";
            else
                compName = $"{cn}.{itemDomain}";

            ComputerNode adnode = new ComputerNode()
            {
                ObjectIdentifier = adobject.ObjectSid.ToString(),
                AllowedToAct = allowedToActPrincipals,
                PrimaryGroupSID = domainsid + "-" + adobject.PrimaryGroupID.ToString(),
                LocalAdmins = new APIResult(),
                PSRemoteUsers = new APIResult(),
                Properties = new ComputerProperties()
                {
                    name = compName.ToUpper(),
                    samaccountname = adobject.SAMAccountName,
                    domainsid = domainsid,
                    domain = domainName.ToUpper(),
                    distinguishedname = adobject.DistinguishedName.ToUpper(),
                    unconstraineddelegation = unconstrained,
                    enabled = enabled,
                    trustedtoauth = trustedToAuth,
                    haslaps = hasLaps,
                    lastlogon = (long)adobject.LastLogon.Subtract(EpochDiff).TotalSeconds,
                    lastlogontimestamp = (long)adobject.LastLogonTimestamp.Subtract(EpochDiff).TotalSeconds,
                    pwdlastset = (long)adobject.PwdLastSet.Subtract(EpochDiff).TotalSeconds,
                    whencreated = (long)adobject.WhenCreated.Subtract(EpochDiff).TotalSeconds,
                    serviceprincipalnames = adobject.ServicePrincipalName,
                    description = adobject.Description,
                    operatingsystem = adobject.OperatingSystem,
                    sidhistory = sidhistorytmp,
                },
                RemoteDesktopUsers = new APIResult(),
                DcomUsers = new APIResult(),
                PrivilegedSessions = new APIResult(),
                Sessions = new APIResult(),
                RegistrySessions = new APIResult(),
                Aces = ACLProcessor.parseAces(adobject.NTSecurityDescriptor, objectType, hasLaps),
                IsDeleted = (adobject.IsDeleted == null) ? false:true,
                IsACLProtected = (adobject.NTSecurityDescriptor.AreAccessRulesProtected || adobject.NTSecurityDescriptor.AreAuditRulesProtected) ? true : false,
            };
            //Update negative values for lastlogon and timestamp, which happens when the object never logged on 
            if (adnode.Properties.lastlogon < 0)
                adnode.Properties.lastlogon = 0;
            if (adnode.Properties.lastlogontimestamp < 0)
                adnode.Properties.lastlogontimestamp = -1;
            //Update negative value for pwdlastset
            if (adnode.Properties.pwdlastset < 0)
                adnode.Properties.pwdlastset = 0;
            return adnode;

        }

    }
}
