using System;
using System.Collections.Generic;
using SOAPHound.OutputTypes;
using SOAPHound.Enums;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace SOAPHound.ADWS
{
    public class Meta
    {
        public int methods { get; set; } = 0;
        public string type { get; set; } = String.Empty;
        public int count { get; set; }
        public int version { get; set; } = 5;
    }

    public abstract class AbstractNode<T>
    {
        public List<T> data { get; set; } = new List<T>();
        public Meta meta { get; set; } = new Meta();

        public AbstractNode(string metaType)
        {
            meta.type = metaType;
        }
    }
    public class OutputComputers : AbstractNode<ComputerNode>
    {
        public OutputComputers() : base("computers")
        {
        }
    }

    public class OutputUsers : AbstractNode<UserNode>
    {
        public OutputUsers() : base("users")
        {
        }
    }


    public class OutputGroups : AbstractNode<GroupNode>
    {
        public OutputGroups() : base("groups")
        {
        }
    }

    public class OutputDomains : AbstractNode<DomainNode>
    {
        public OutputDomains() : base("domains")
        {
        }
    }

    public class OutputGPOs : AbstractNode<GPONode>
    {
        public OutputGPOs() : base("gpos")
        {
        }
    }

    public class OutputOUs : AbstractNode<OUNode>
    {
        public OutputOUs() : base("ous")
        {
        }
    }

    public class OutputContainers : AbstractNode<ContainerNode>
    {
        public OutputContainers() : base("containers")
        {
        }
    }


    public abstract class BasicNode
    {
        public string ObjectIdentifier { get; set; }
        public IEnumerable<Ace> Aces { get; set; }
        public Boolean IsDeleted { get; set; }
        public Boolean IsACLProtected { get; set; } = false;
        
    }

    public abstract class Node : BasicNode
    {
        public string PrimaryGroupSID { get; set; }
        public string[] AllowedToDelegate { get; set; } = Array.Empty<string>();
        public string[] HasSIDHistory { get; set; } = Array.Empty<string>();
    }

    public class ComputerNode : Node
    {
        public List<TypedPrincipal> AllowedToAct { get; set; } = new List<TypedPrincipal>();
        public APIResult LocalAdmins { get; set; }
        public APIResult PSRemoteUsers { get; set; }
        public ComputerProperties Properties { get; set; }
        public APIResult RemoteDesktopUsers { get; set; }
        public APIResult DcomUsers { get; set; }
        public APIResult PrivilegedSessions { get; set; }
        public APIResult Sessions { get; set; }
        public APIResult RegistrySessions { get; set; }
    }



    public class UserNode : Node
    {
        public string[] SPNTargets { get; set; }
        public UserProperties Properties { get; set; }
    }

    public class GroupNode : BasicNode
    {
        public TypedPrincipal[] Members { get; set; }
        public GroupProperties Properties { get; set; }
    }

    public class DomainNode : BasicNode
    {
        public TypedPrincipal[] ChildObjects { get; set; } = Array.Empty<TypedPrincipal>();
        public DomainProperties Properties { get; set; }
        public DomainTrust[] Trusts { get; set; } = Array.Empty<DomainTrust>();
        public GPLink[] Links { get; set; } = Array.Empty<GPLink>();
        public ResultingGPOChanges GPOChanges { get; set; } = new ResultingGPOChanges();

    }

    public class GPONode : BasicNode
    {
        public GPOProperties Properties { get; set; }
    }

    public class OUNode : BasicNode
    {
        public ResultingGPOChanges GPOChanges { get; set; } = new ResultingGPOChanges();
        public OUProperties Properties { get; set; }
        public GPLink[] Links { get; set; }
        public TypedPrincipal[] ChildObjects { get; set; }
    }

    public class ContainerNode : BasicNode
    {
        public ContainerProperties Properties { get; set; }
        public TypedPrincipal[] ChildObjects { get; set; }
    }

    public class DomainTrust
    {
        public string TargetDomainSid { get; set; }
        public string TargetDomainName { get; set; }
        public bool IsTransitive { get; set; }
        public bool SidFilteringEnabled { get; set; }
        public int TrustDirection { get; set; }
        public int TrustType { get; set; }
    }

    public abstract class BasicProperties
    {
        public string name { get; set; }
        public string domainsid { get; set; }
        public string domain { get; set; }
        public string distinguishedname { get; set; }
        public Boolean highvalue { get; set; } = false; 

    }

    public abstract class Properties : BasicProperties
    {
        public string description { get; set; }
        public Boolean unconstraineddelegation { get; set; }
        public Boolean enabled { get; set; }
        public Boolean trustedtoauth { get; set; }
        public long lastlogon { get; set; }
        public long lastlogontimestamp { get; set; }
        public long pwdlastset { get; set; }
        public long whencreated { get; set; }
        public string[] sidhistory { get; set; } = Array.Empty<string>();
        public string[] serviceprincipalnames { get; set; } = Array.Empty<string>();
    }

    public class ComputerProperties : Properties
    {
        public Boolean haslaps { get; set; }

        public string operatingsystem { get; set; }
        public string samaccountname { get; set; }
    }

    public class UserProperties : Properties
    {
        public string samaccountname { get; set; }
        public Boolean passwordnotreqd { get; set; }
        public Boolean dontreqpreauth { get; set; }
        public Boolean pwdneverexpires { get; set; }
        public Boolean sensitive { get; set; }
        public Boolean hasspn { get; set; } = false;
        public Boolean admincount { get; set; }
        public string displayName { get; set; }
        public string email { get; set; }
        public string title { get; set; }
        public string homedirectory { get; set; }
        public string userpassword { get; set; }
        public string unixpassword { get; set; }
        public string unicodepassword { get; set; }
        public string sfupassword { get; set; }
        public string logonscript { get; set; }
    }

    public class GroupProperties : BasicProperties
    {
        public string samaccountname { get; set; }
        public string description { get; set; }
        public Boolean admincount { get; set; }
        public long whencreated { get; set; }
    }


    public class DomainProperties : BasicProperties
    {
        public string description { get; set; }
        public string functionallevel { get; set; }
        public long whencreated { get; set; }
    }

    public class GPOProperties : BasicProperties
    {
        public string description { get; set; }
        public long whencreated { get; set; }
        public string gpcpath { get; set; }
    }

    public class OUProperties : BasicProperties
    {
        public string description { get; set; }
        public long whencreated { get; set; }
        public Boolean blocksinheritance { get; set; } = false;
    }

    public class ContainerProperties : BasicProperties
    { 
    
    }
    public class Ace
    {
        public string RightName { get; set; }
        public Boolean IsInherited { get; set; }
        public string PrincipalSID { get; set; }
        [JsonConverter(typeof(StringEnumConverter))]
        public Label PrincipalType { get; set; }
    }




}
