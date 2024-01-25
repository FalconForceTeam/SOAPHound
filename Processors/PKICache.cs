using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.Serialization;
using SOAPHound.Enums;
using SOAPHound.OutputTypes;

namespace SOAPHound.Processors
{

    public static class PKICache
    {
        static PKICache()
        {

            TemplateToCACache = new Dictionary<string, List<string>>();
        }

        private static Dictionary<string, List<string>> TemplateToCACache { get; set; }

        internal static void AddTemplateCA(string template, string CA)
        {
            if (!TemplateToCACache.ContainsKey(template))
                TemplateToCACache.Add(template, new List<string>());
            TemplateToCACache[template].Add(CA);

        }

        internal static List<string> GetTemplateCA(string template)
        {
            if (TemplateToCACache.ContainsKey(template))
                return TemplateToCACache[template];
            else
                return new List<string>();
        }




    }
}