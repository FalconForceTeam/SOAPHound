using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;

namespace SOAPHound.Enums
{
    [JsonConverter(typeof(StringEnumConverter))]
    public enum TrustDirection
    {
        Disabled = 0,
        Inbound = 1,
        Outbound = 2,
        Bidirectional = 3
    }
    [JsonConverter(typeof(StringEnumConverter))]
    public enum TrustType
    {
        ParentChild = 0,
        CrossLink = 1,
        Forest = 2,
        External = 3,
        Unknown = 4
    }

    [Flags]
    public enum TrustAttributes
    {
        NonTransitive = 0x1,
        UplevelOnly = 0x2,
        FilterSids = 0x4,
        ForestTransitive = 0x8,
        CrossOrganization = 0x10,
        WithinForest = 0x20,
        TreatAsExternal = 0x40,
        TrustUsesRc4 = 0x80,
        TrustUsesAes = 0x100,
        CrossOrganizationNoTGTDelegation = 0x200,
        PIMTrust = 0x400
    }
}