using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using SOAPHound.Enums;
using SOAPHound.ADWS;
using SOAPHound.OutputTypes;
using SOAPHound;
using System.Linq;

namespace SOAPHound.Processors
{
    public static class ACLProcessor
    {

        public static IEnumerable<Ace> parseAces(ActiveDirectorySecurity NTSecurityDescriptor, Label objectType, bool hasLaps)
        {

            if (NTSecurityDescriptor != null)
            {
                // Get owner
                var ownerSid = NTSecurityDescriptor.GetOwner(typeof(SecurityIdentifier));
                if (ownerSid != null)
                {
                    var resolvedOwner = ADWSUtils.ResolveIDAndType(ownerSid.ToString());
                    if (resolvedOwner != null)
                        yield return new Ace
                        {
                            PrincipalType = resolvedOwner.ObjectType,
                            PrincipalSID = resolvedOwner.ObjectIdentifier,
                            RightName = EdgeNames.Owns,
                            IsInherited = false,
                        };
                }

                foreach (ActiveDirectoryAccessRule rule in NTSecurityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {

                    if (rule.IdentityReference.ToString().StartsWith("S-1-5-21"))
                    {
                        var aceRights = rule.ActiveDirectoryRights;
                        var aceType = rule.ObjectType.ToString().ToLower();
                        var inherited = rule.IsInherited;
                        var resolvedPrincipal = ADWSUtils.ResolveIDAndType(rule.IdentityReference.ToString());

                        if (objectType == Label.CA)
                        {
                            var rights = (CertificationAuthorityRights)rule.ActiveDirectoryRights;
                            if (((rights & CertificationAuthorityRights.ManageCA) == CertificationAuthorityRights.ManageCA))
                                yield return new Ace
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.ManageCA,
                                };

                            if (((rights & CertificationAuthorityRights.ManageCertificates) == CertificationAuthorityRights.ManageCertificates))
                                yield return new Ace
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.ManageCertificates,
                                };
                            if (((rights & CertificationAuthorityRights.Auditor) == CertificationAuthorityRights.Auditor))
                                yield return new Ace
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.Auditor,
                                };
                            if (((rights & CertificationAuthorityRights.Operator) == CertificationAuthorityRights.Operator))
                                yield return new Ace
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.Operator,
                                };
                        }


                        //GenericAll applies to every object
                        if (aceRights.HasFlag(ActiveDirectoryRights.GenericAll))
                        {
                            if (aceType == ACEGuids.AllGuid || aceType == "")
                                yield return new Ace
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.GenericAll
                                };
                            //This is a special case. If we don't continue here, every other ACE will match because GenericAll includes all other permissions
                            continue;
                        }
                        //WriteDACL and WriteOwner are always useful no matter what the object type is as well because they enable all other attacks
                        if (aceRights.HasFlag(ActiveDirectoryRights.WriteDacl))
                            yield return new Ace
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.WriteDacl,
                            };

                        if (aceRights.HasFlag(ActiveDirectoryRights.WriteOwner))
                            yield return new Ace
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.WriteOwner,
                            };

                        //Allows a principal to add itself to a group and no one else
                        if (aceRights.HasFlag(ActiveDirectoryRights.Self) &&
                            !aceRights.HasFlag(ActiveDirectoryRights.WriteProperty) &&
                            !aceRights.HasFlag(ActiveDirectoryRights.GenericWrite) && objectType == Label.Group &&
                            aceType == ACEGuids.WriteMember)
                            yield return new Ace
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.AddSelf
                            };

                        //Process object type specific ACEs. Extended rights apply to users, domains, and computers
                        if (aceRights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                        {
                            if (objectType == Label.Domain)
                            {
                                if (aceType == ACEGuids.DSReplicationGetChanges)
                                    yield return new Ace
                                    {
                                        PrincipalType = resolvedPrincipal.ObjectType,
                                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                        IsInherited = inherited,
                                        RightName = EdgeNames.GetChanges
                                    };
                                else if (aceType == ACEGuids.DSReplicationGetChangesAll)
                                    yield return new Ace
                                    {
                                        PrincipalType = resolvedPrincipal.ObjectType,
                                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                        IsInherited = inherited,
                                        RightName = EdgeNames.GetChangesAll
                                    };
                                else if (aceType == ACEGuids.DSReplicationGetChangesInFilteredSet)
                                    yield return new Ace
                                    {
                                        PrincipalType = resolvedPrincipal.ObjectType,
                                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                        IsInherited = inherited,
                                        RightName = EdgeNames.GetChangesInFilteredSet
                                    };
                                else if (aceType == ACEGuids.AllGuid || aceType == "")
                                    yield return new Ace
                                    {
                                        PrincipalType = resolvedPrincipal.ObjectType,
                                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                        IsInherited = inherited,
                                        RightName = EdgeNames.AllExtendedRights
                                    };
                            }
                            else if (objectType == Label.User)
                            {
                                if (aceType == ACEGuids.UserForceChangePassword)
                                    yield return new Ace
                                    {
                                        PrincipalType = resolvedPrincipal.ObjectType,
                                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                        IsInherited = inherited,
                                        RightName = EdgeNames.ForceChangePassword
                                    };
                                else if (aceType == ACEGuids.AllGuid || aceType == "")
                                    yield return new Ace
                                    {
                                        PrincipalType = resolvedPrincipal.ObjectType,
                                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                        IsInherited = inherited,
                                        RightName = EdgeNames.AllExtendedRights
                                    };
                            }
                            else if (objectType == Label.Computer)
                            {
                                //ReadLAPSPassword is only applicable if the computer actually has LAPS. Check the world readable property ms-mcs-admpwdexpirationtime
                                if (hasLaps)
                                {
                                    if (aceType == ACEGuids.AllGuid || aceType == "")
                                        yield return new Ace
                                        {
                                            PrincipalType = resolvedPrincipal.ObjectType,
                                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                            IsInherited = inherited,
                                            RightName = EdgeNames.AllExtendedRights
                                        };
                                    /* to be checked and fixed
                                        else if (mappedGuid is "ms-mcs-admpwd")
                                        yield return new Ace
                                        {
                                            PrincipalType = resolvedPrincipal.ObjectType,
                                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                            IsInherited = inherited,
                                            RightName = EdgeNames.ReadLAPSPassword
                                        }; */
                                }
                            }
                        }

                        //GenericWrite encapsulates WriteProperty, so process them in tandem to avoid duplicate edges
                        if (aceRights.HasFlag(ActiveDirectoryRights.GenericWrite) ||
                            aceRights.HasFlag(ActiveDirectoryRights.WriteProperty))
                        {
                            if (objectType == Label.User || objectType == Label.Group || objectType == Label.Computer || objectType == Label.GPO)
                                if (aceType == ACEGuids.AllGuid || aceType == "")
                                    yield return new Ace
                                    {
                                        PrincipalType = resolvedPrincipal.ObjectType,
                                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                        IsInherited = inherited,
                                        RightName = EdgeNames.GenericWrite
                                    };

                            if (objectType == Label.User && aceType == ACEGuids.WriteSPN)
                                yield return new Ace
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.WriteSPN
                                };
                            else if (objectType == Label.Computer && aceType == ACEGuids.WriteAllowedToAct)
                                yield return new Ace
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.AddAllowedToAct
                                };
                            else if (objectType == Label.Computer && aceType == ACEGuids.UserAccountRestrictions && !resolvedPrincipal.ObjectIdentifier.EndsWith("-512"))
                                yield return new Ace
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.WriteAccountRestrictions
                                };
                            else if (objectType == Label.Group && aceType == ACEGuids.WriteMember)
                                yield return new Ace
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.AddMember
                                };
                            else if ((objectType == Label.User || objectType == Label.Computer) && aceType == ACEGuids.AddKeyPrincipal)
                                yield return new Ace
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.AddKeyCredentialLink
                                };
                        }

                        //Enrollemnt flag for PKI
                        if (aceType == ACEGuids.Enrollment)
                            yield return new Ace
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.Enroll,

                            };
                        if (aceType == ACEGuids.AutoEnrollment)
                            yield return new Ace
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.AutoEnroll,

                            };

                    }
                }

            }

        }


    }
}