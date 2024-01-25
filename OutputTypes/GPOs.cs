using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SOAPHound.OutputTypes
{
    public class GPLink
    {
        private string _guid;

        public bool IsEnforced { get; set; }

        public string GUID
        {
            get => _guid;
            set => _guid = value?.ToUpper();
        }
    }

    public class ResultingGPOChanges
    {
        public TypedPrincipal[] LocalAdmins { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] RemoteDesktopUsers { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] DcomUsers { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] PSRemoteUsers { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] AffectedComputers { get; set; } = Array.Empty<TypedPrincipal>();
    }

    public class APIResult
    {
        public Boolean Collected { get; set; } = false;
        public string FailureReason { get; set; } = null;
        public string[] Results { get; set; } = Array.Empty<string>();

    }
}
