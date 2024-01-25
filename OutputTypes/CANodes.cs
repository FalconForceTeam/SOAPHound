using System;
using System.Collections.Generic;
using SOAPHound.Enums;
using Newtonsoft.Json;

namespace SOAPHound.ADWS
{

    public class OutputCA
    {
        public List<CA> data { get; set; } = new List<CA>();
        public Meta meta { get; set; } = new Meta();

        public OutputCA()
        {
            meta.type = "gpos";
        }
    }

    public class OutputCATemplate
    {
        public List<CATemplate> data { get; set; } = new List<CATemplate>();
        public Meta meta { get; set; } = new Meta();

        public OutputCATemplate()
        {
            meta.type = "gpos";
        }
    }

    public class CATemplate
    {
        public string ObjectIdentifier { get; set; }
        public IEnumerable<Ace> Aces { get; set; }
        public CATemplateProperties Properties { get; set; }
    }

    public class CATemplateProperties
    {
        public string name { get; set; }
        public Boolean highvalue { get; set; } = false;
        [JsonProperty("Template Name")]
        public string templatename { get; set; }
        [JsonProperty("Display Name")]
        public string displayname { get; set; }
        [JsonProperty("Certificate Authorities")]
        public List<string> certificateauthorities { get; set; }
        public Boolean Enabled { get; set; }
        [JsonProperty("Client Authentication")]
        public Boolean clientauthentication { get; set; }
        [JsonProperty("Enrollment Agent")]
        public Boolean enrollmentagent { get; set; }
        [JsonProperty("Any Purpose")]
        public Boolean anypurpose { get; set; }
        [JsonProperty("Enrollee Supplies Subject")]
        public Boolean enrolleesuppliessubject { get; set; }
        [JsonProperty("Certificate Name Flag")]
        public List<msPKICertificateNameFlag> certificatenameflag { get; set; }
        [JsonProperty("Enrollment Flag")]
        public List<msPKIEnrollmentFlag> enrollmentflag { get; set; }
        [JsonProperty("Private Key Flag")]
        public List<msPKIPrivateKeyFlag> privatekeyflag { get; set; }
        [JsonProperty("Extended Key Usage")]
        public List<string> extendedkeyusage { get; set; }
        [JsonProperty("Requires Manager Approval")]
        public Boolean requiresmanagerapproval { get; set; }
        [JsonProperty("Requires Key Archival")]
        public Boolean requireskeyarchival { get; set; }
        [JsonProperty("Authorized Signatures Required")]
        public int authorizedsignaturesrequired { get; set; }
        [JsonProperty("Validity Period")]
        public string validityperiod { get; set; }
        [JsonProperty("Renewal Period")]
        public string renewalperiod { get; set; }
        [JsonProperty("Minimum RSA Key Length")]
        public int minimumrsakeylength { get; set; }
        public string domain { get; set; }
        public string type { get; set; }
    }



 
    public class CA
    {
        public string ObjectIdentifier { get; set; }
        public IEnumerable<Ace> Aces { get; set; }
        public CAProperties Properties { get; set; }
    }

    public class CAProperties
    {
        public string name { get; set; }
        public Boolean highvalue { get; set; } = false;
        public string domain { get; set; }
        [JsonProperty("CA Name")]
        public string caname { get; set; }
        [JsonProperty("DNS Name")]
        public string dnsname { get; set; }
        [JsonProperty("Certificate Subject")]
        public string certificatesubject { get; set; }
        [JsonProperty("Certificate Serial Number")]
        public string certificateserialnumber { get; set; }
        [JsonProperty("Certificate Validity Start")]
        public DateTime certificatevaliditystart { get; set; }
        [JsonProperty("Certificate Validity End")]
        public DateTime certificatevalidityend { get; set; }
        [JsonProperty("Web Enrollment")]
        public string webenrollment { get; set; } = "";
        [JsonProperty("User Specified SAN")]
        public string userspecifiedsan { get; set; } = "";
        [JsonProperty("Request Disposition")]
        public string requestdisposition { get; set; } = "";
        [JsonProperty("Enforce Encryption For Requests")]
        public string enforceencryptionforrequests { get; set; } = "";
        public string type { get; set; }
    }
}
