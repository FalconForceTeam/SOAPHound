using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

/*

This file includes code from Certify, which has the following license. 
 
Certify is provided under the 3-clause BSD license below.

*************************************************************

Copyright (c) 2021, Will Schroeder and Lee Christensen
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    The names of its contributors may not be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

namespace SOAPHound.Enums
{
    public class FlagCaseNamingStrategy : CamelCaseNamingStrategy
    {
        protected override string ResolvePropertyName(string name)
        {
            return (Regex.Replace(name.ToLower(), @"((^\w)|(\s|\p{P})\w)", match => match.Value.ToUpper())).Replace("_", ""); 
        }
    }

    [Flags]
    [JsonConverter(typeof(StringEnumConverter),typeof(FlagCaseNamingStrategy))]
    public enum msPKICertificateNameFlag : uint
    {
        ENROLLEE_SUPPLIES_SUBJECT = 0x00000001,
        ADD_EMAIL = 0x00000002,
        ADD_OBJ_GUID = 0x00000004,
        OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008,
        ADD_DIRECTORY_PATH = 0x00000100,
        ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000,
        SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000,
        SUBJECT_ALT_REQUIRE_SPN = 0x00800000,
        SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000,
        SUBJECT_ALT_REQUIRE_UPN = 0x02000000,
        SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000,
        SUBJECT_ALT_REQUIRE_DNS = 0x08000000,
        SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000,
        SUBJECT_REQUIRE_EMAIL = 0x20000000,
        SUBJECT_REQUIRE_COMMON_NAME = 0x40000000,
        SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000,
    }

    [Flags]
    [JsonConverter(typeof(StringEnumConverter), typeof(FlagCaseNamingStrategy))]
    public enum msPKIPrivateKeyFlag : uint
    { 
        REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001,
        EXPORTABLE_KEY = 0x00000010,
        STRONG_KEY_PROTECTION_REQUIRED = 0x00000020,
        REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040,
        REQUIRE_SAME_KEY_RENEWAL = 0x00000080,
        USE_LEGACY_PROVIDER = 0x00000100,
        ATTEST_NONE = 0x00000000,
        ATTEST_REQUIRED = 0x00002000,
        ATTEST_PREFERRED = 0x00001000,
        ATTESTATION_WITHOUT_POLICY = 0x00004000,
        EK_TRUST_ON_USE = 0x00000200,
        EK_VALIDATE_CERT = 0x00000400,
        EK_VALIDATE_KEY = 0x00000800,
        HELLO_LOGON_KEY = 0x00200000,
    }

    [Flags]
    [JsonConverter(typeof(StringEnumConverter), typeof(FlagCaseNamingStrategy))]
    public enum msPKIEnrollmentFlag : uint
    {
        NONE = 0x00000000,
        INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001,
        PEND_ALL_REQUESTS = 0x00000002,
        PUBLISH_TO_KRA_CONTAINER = 0x00000004,
        PUBLISH_TO_DS = 0x00000008,
        AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010,
        AUTO_ENROLLMENT = 0x00000020,
        CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x80,
        PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040,
        USER_INTERACTION_REQUIRED = 0x00000100,
        ADD_TEMPLATE_NAME = 0x200,
        REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400,
        ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800,
        ADD_OCSP_NOCHECK = 0x00001000,
        ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000,
        NOREVOCATIONINFOINISSUEDCERTS = 0x00004000,
        INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000,
        ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000,
        ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000,
        SKIP_AUTO_RENEWAL = 0x00040000,
        NO_SECURITY_EXTENSION = 0x00080000
    }

    public class msPKIExtendedKeyUsage
    {
        public string AnyPurpose = "2.5.29.37.0";
        public string ClientAuthentication = "1.3.6.1.5.5.7.3.2";
        public string PKINITClientAuthentication = "1.3.6.1.5.2.3.4";
        public string SmartcardLogon = "1.3.6.1.4.1.311.20.2.2";
        public string CertificateRequestAgent = "1.3.6.1.4.1.311.20.2.1";
        public string CertificateRequestAgentPolicy = "1.3.6.1.4.1.311.20.2.1";
    }

    [Flags]
    public enum CertificationAuthorityRights : uint
    {
        ManageCA = 1,               // Administrator
        ManageCertificates = 2,     // Officer
        Auditor = 4,
        Operator = 8,
        Read = 256,
        Enroll = 512,
    }
    public class OidConverter
    {
        static Dictionary<string, string> OidLookup = new Dictionary<string, string>();

        //Static constructor
        static OidConverter()
        {
            //https://www.pkisolutions.com/object-identifiers-oid-in-pki/
            OidLookup["1.3.6.1.4.1.311.76.6.1"] = "Windows Update";
            OidLookup["1.3.6.1.4.1.311.10.3.11"] = "Key Recovery";
            OidLookup["1.3.6.1.4.1.311.10.3.25"] = "Windows Third Party Application Component";
            OidLookup["1.3.6.1.4.1.311.21.6"] = "Key Recovery Agent";
            OidLookup["1.3.6.1.4.1.311.10.3.6"] = "Windows System Component Verification";
            OidLookup["1.3.6.1.4.1.311.61.4.1"] = "Early Launch Antimalware Drive";
            OidLookup["1.3.6.1.4.1.311.10.3.23"] = "Windows TCB Component";
            OidLookup["1.3.6.1.4.1.311.61.1.1"] = "Kernel Mode Code Signing";
            OidLookup["1.3.6.1.4.1.311.10.3.26"] = "Windows Software Extension Verification";
            OidLookup["2.23.133.8.3"] = "Attestation Identity Key Certificate";
            OidLookup["1.3.6.1.4.1.311.76.3.1"] = "Windows Store";
            OidLookup["1.3.6.1.4.1.311.10.6.1"] = "Key Pack Licenses";
            OidLookup["1.3.6.1.4.1.311.20.2.2"] = "Smart Card Logon";
            OidLookup["1.3.6.1.5.2.3.5"] = "KDC Authentication";
            OidLookup["1.3.6.1.5.5.7.3.7"] = "IP security use";
            OidLookup["1.3.6.1.4.1.311.10.3.8"] = "Embedded Windows System Component Verification";
            OidLookup["1.3.6.1.4.1.311.10.3.20"] = "Windows Kits Component";
            OidLookup["1.3.6.1.5.5.7.3.6"] = "IP security tunnel termination";
            OidLookup["1.3.6.1.4.1.311.10.3.5"] = "Windows Hardware Driver Verification";
            OidLookup["1.3.6.1.5.5.8.2.2"] = "IP security IKE intermediate";
            OidLookup["1.3.6.1.4.1.311.10.3.39"] = "Windows Hardware Driver Extended Verification";
            OidLookup["1.3.6.1.4.1.311.10.6.2"] = "License Server Verification";
            OidLookup["1.3.6.1.4.1.311.10.3.5.1"] = "Windows Hardware Driver Attested Verification";
            OidLookup["1.3.6.1.4.1.311.76.5.1"] = "Dynamic Code Generato";
            OidLookup["1.3.6.1.5.5.7.3.8"] = "Time Stamping";
            OidLookup["1.3.6.1.4.1.311.10.3.4.1"] = "File Recovery";
            OidLookup["1.3.6.1.4.1.311.2.6.1"] = "SpcRelaxedPEMarkerCheck";
            OidLookup["2.23.133.8.1"] = "Endorsement Key Certificate";
            OidLookup["1.3.6.1.4.1.311.2.6.2"] = "SpcEncryptedDigestRetryCount";
            OidLookup["1.3.6.1.4.1.311.10.3.4"] = "Encrypting File System";
            OidLookup["1.3.6.1.5.5.7.3.1"] = "Server Authentication";
            OidLookup["1.3.6.1.4.1.311.61.5.1"] = "HAL Extension";
            OidLookup["1.3.6.1.5.5.7.3.4"] = "Secure Email";
            OidLookup["1.3.6.1.5.5.7.3.5"] = "IP security end system";
            OidLookup["1.3.6.1.4.1.311.10.3.9"] = "Root List Signe";
            OidLookup["1.3.6.1.4.1.311.10.3.30"] = "Disallowed List";
            OidLookup["1.3.6.1.4.1.311.10.3.19"] = "Revoked List Signe";
            OidLookup["1.3.6.1.4.1.311.10.3.21"] = "Windows RT Verification";
            OidLookup["1.3.6.1.4.1.311.10.3.10"] = "Qualified Subordination";
            OidLookup["1.3.6.1.4.1.311.10.3.12"] = "Document Signing";
            OidLookup["1.3.6.1.4.1.311.10.3.24"] = "Protected Process Verification";
            OidLookup["1.3.6.1.4.1.311.80.1"] = "Document Encryption";
            OidLookup["1.3.6.1.4.1.311.10.3.22"] = "Protected Process Light Verification";
            OidLookup["1.3.6.1.4.1.311.21.19"] = "Directory Service Email Replication";
            OidLookup["1.3.6.1.4.1.311.21.5"] = "Private Key Archival";
            OidLookup["1.3.6.1.4.1.311.10.5.1"] = "Digital Rights";
            OidLookup["1.3.6.1.4.1.311.10.3.27"] = "Preview Build Signing";
            OidLookup["1.3.6.1.4.1.311.20.2.1"] = "Certificate Request Agent";
            OidLookup["2.23.133.8.2"] = "Platform Certificate";
            OidLookup["1.3.6.1.4.1.311.20.1"] = "CTL Usage";
            OidLookup["1.3.6.1.5.5.7.3.9"] = "OCSP Signing";
            OidLookup["1.3.6.1.5.5.7.3.3"] = "Code Signing";
            OidLookup["1.3.6.1.4.1.311.10.3.1"] = "Microsoft Trust List Signing";
            OidLookup["1.3.6.1.4.1.311.10.3.2"] = "Microsoft Time Stamping";
            OidLookup["1.3.6.1.4.1.311.76.8.1"] = "Microsoft Publishe";
            OidLookup["1.3.6.1.5.5.7.3.2"] = "Client Authentication";
            OidLookup["1.3.6.1.5.2.3.4"] = "PKIINIT Client Authentication";
            OidLookup["1.3.6.1.4.1.311.10.3.13"] = "Lifetime Signing";
            OidLookup["2.5.29.37.0"] = "Any Purpose";
            OidLookup["1.3.6.1.4.1.311.64.1.1"] = "Server Trust";
            OidLookup["1.3.6.1.4.1.311.10.3.7"] = "OEM Windows System Component Verification";
        }
 
        public List<string> LookupOid(string[] oids)
        {
            List<string> oidnames = new List<string> { };
            if (oids != null)
            {
                foreach (string oid in oids)
                {
                    if (OidLookup.ContainsKey(oid))
                    {
                        oidnames.Add(OidLookup[oid]);
                    }
                    else
                    {
                        oidnames.Add(oid);
                    }
                }
            }
            return oidnames;

        }
    }
}
