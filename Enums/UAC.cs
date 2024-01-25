using System;

namespace SOAPHound.Enums
{
    [Flags]
    public enum UacFlags
    {
        Script = 0x1,
        AccountDisable = 0x2,
        HomeDirRequired = 0x8,
        Lockout = 0x10,
        PasswordNotRequired = 0x20,
        PasswordCantChange = 0x40,
        EncryptedTextPwdAllowed = 0x80,
        TempDuplicateAccount = 0x100,
        NormalAccount = 0x200,
        InterdomainTrustAccount = 0x800,
        WorkstationTrustAccount = 0x1000,
        ServerTrustAccount = 0x2000,
        DontExpirePassword = 0x10000,
        MnsLogonAccount = 0x20000,
        SmartcardRequired = 0x40000,
        TrustedForDelegation = 0x80000,
        NotDelegated = 0x100000,
        UseDesKeyOnly = 0x200000,
        DontReqPreauth = 0x400000,
        PasswordExpired = 0x800000,
        TrustedToAuthForDelegation = 0x1000000,
        PartialSecretsAccount = 0x04000000
    }
}