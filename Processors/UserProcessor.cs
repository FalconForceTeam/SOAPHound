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
    class UserProcessor
    {
        public UserNode parseUserObject(ADObject adobject, string domainName)
        {
            DateTime EpochDiff = new DateTime(1970, 1, 1);
            bool enabled, trustedToAuth, sensitive, dontReqPreAuth, passwdNotReq, unconstrained, pwdNeverExpires;

            // Extract domainsid from User SID
            string domainsid = adobject.ObjectSid.ToString().Substring(0, adobject.ObjectSid.ToString().LastIndexOf('-'));

            //checking if SIDHistory is not null, then convert SecurityIdentifier[] to String[] withn LINQ (triggers exception if null)
            string[] sidhistorytmp = new string[] { };
            if (adobject.SIDHistory != null)
            {
                sidhistorytmp = adobject.SIDHistory.Select(i => i.ToString()).ToArray();
            }
            else
                sidhistorytmp = new string[] { };


            var uac = adobject.UserAccountControl.ToString();

            if (int.TryParse(uac, out var flag))
            {
                var flags = (UacFlags)flag;
                enabled = (flags & UacFlags.AccountDisable) == 0;
                trustedToAuth = (flags & UacFlags.TrustedToAuthForDelegation) != 0;
                sensitive = (flags & UacFlags.NotDelegated) != 0;
                dontReqPreAuth = (flags & UacFlags.DontReqPreauth) != 0;
                passwdNotReq = (flags & UacFlags.PasswordNotRequired) != 0;
                unconstrained = (flags & UacFlags.TrustedForDelegation) != 0;
                pwdNeverExpires = (flags & UacFlags.DontExpirePassword) != 0;
            }
            else
            {
                trustedToAuth = false;
                enabled = true;
                sensitive = false;
                dontReqPreAuth = false;
                passwdNotReq = false;
                unconstrained = false;
                pwdNeverExpires = false;
            }

          
            ////TODO allowedtodelegate

            Label objectType = ADWSUtils.ResolveIDAndType(adobject.ObjectSid.ToString()).ObjectType;

            UserNode adnode = new UserNode()
            {

                ObjectIdentifier = adobject.ObjectSid.ToString(),
                PrimaryGroupSID = domainsid + "-" + adobject.PrimaryGroupID.ToString(),
                Properties = new UserProperties()
                {
                    name = adobject.SAMAccountName.ToUpper() + "@" + domainName.ToUpper(),
                    samaccountname = adobject.SAMAccountName,
                    domainsid = domainsid,
                    domain = domainName.ToUpper(),
                    distinguishedname = adobject.DistinguishedName.ToUpper(),
                    unconstraineddelegation = unconstrained,
                    trustedtoauth = trustedToAuth,
                    enabled = enabled,
                    passwordnotreqd = passwdNotReq,
                    dontreqpreauth = dontReqPreAuth,
                    pwdneverexpires = pwdNeverExpires,
                    sensitive = sensitive,
                    lastlogon = (long)adobject.LastLogon.Subtract(EpochDiff).TotalSeconds, 
                    lastlogontimestamp = (long)adobject.LastLogonTimestamp.Subtract(EpochDiff).TotalSeconds, 
                    pwdlastset = (long)adobject.PwdLastSet.Subtract(EpochDiff).TotalSeconds,
                    whencreated = (long)adobject.WhenCreated.Subtract(EpochDiff).TotalSeconds,
                    serviceprincipalnames = adobject.ServicePrincipalName,
                    description = adobject.Description,
                    sidhistory = sidhistorytmp,
                    displayName = adobject.DisplayName,
                    admincount = (adobject.AdminCount > 0),
                    email = adobject.Email,
                    title = adobject.Title,
                    homedirectory = adobject.HomeDirectory,
                    userpassword = adobject.UserPassword,
                    unixpassword = adobject.UnixUserPassword,
                    unicodepassword = adobject.UnicodePassword,
                    sfupassword = adobject.MsSFU30Password,
                    logonscript = adobject.ScriptPath,
                },
                Aces = ACLProcessor.parseAces(adobject.NTSecurityDescriptor, objectType, false),
                IsDeleted = (adobject.IsDeleted == null) ? false : true,
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
            //Update hasspn attribute
            if (adnode.Properties.serviceprincipalnames != null)
                adnode.Properties.hasspn = (adobject.ServicePrincipalName.Length > 0);
            else
                adnode.Properties.hasspn = false;
            return adnode;

        }

    }
}
