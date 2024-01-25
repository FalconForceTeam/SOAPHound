using System.Collections.Concurrent;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization;
using SOAPHound.Enums;
using SOAPHound.OutputTypes;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System.Linq;
using System.Diagnostics;

namespace SOAPHound.Processors
{
    

    // We're using the WCF datacontract to serialize the cache as a JSON object

    public static class Cache
    {
        static Cache()
        {
            ValueToIdCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); //added OrdinalIgnoreCase to use case insensitive comparisons for gplink->gpo
            IdToTypeCache = new Dictionary<string, Label>();
        }

        // This class is here to work aroud the limitation of NewtonSoft in deserializing static classes.
        [DataContract]
        internal class SerializeableCache
        {
            [DataMember] public Dictionary<string, Label> IdToTypeCache { get; set; }

            [DataMember] public Dictionary<string, string> ValueToIdCache { get; set; }
        }

        public class CacheContractResolver : DefaultContractResolver
        {
            private static readonly CacheContractResolver Instance = new CacheContractResolver();
            public static readonly JsonSerializerSettings Settings = new JsonSerializerSettings()
            {
                ContractResolver = Instance
            };

            protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
            {
                var prop = base.CreateProperty(member, memberSerialization);
                if (!prop.Writable && (member as PropertyInfo)?.GetSetMethod(true) != null)
                {
                    prop.Writable = true;
                }
                return prop;
            }

        }

        public static void Deserialize(string path)
        {
            var json = File.ReadAllText(path);
            SerializeableCache tempCache = JsonConvert.DeserializeObject<SerializeableCache>(json, CacheContractResolver.Settings);
            Cache.ValueToIdCache = new Dictionary<string,string>(tempCache.ValueToIdCache, StringComparer.OrdinalIgnoreCase);
            Cache.IdToTypeCache = tempCache.IdToTypeCache;
        }

        public static void Serialize(string path)
        {
            SerializeableCache tempCache = new SerializeableCache();
            tempCache.IdToTypeCache = Cache.IdToTypeCache;
            tempCache.ValueToIdCache = Cache.ValueToIdCache;
            var serialized = JsonConvert.SerializeObject(tempCache);
            File.WriteAllText(path, serialized);
        }

        public static Dictionary<string, Label> IdToTypeCache { get; private set; }

        public static Dictionary<string, string> ValueToIdCache { get; private set; }



        internal static void AddConvertedValue(string key, string value)
        {
            ValueToIdCache.Add(key, value);
        }

   
        internal static void AddType(string key, Label value)
        {
            IdToTypeCache.Add(key, value);
        }

        internal static bool GetConvertedValue(string key, out string value)
        {
            return ValueToIdCache.TryGetValue(key, out value);
        }

        //internal static bool GetPrefixedValue(string key, string domain, out string value)
        //{
        //    return ValueToIdCache.TryGetValue(GetPrefixKey(key, domain), out value);
        //}

        internal static bool GetIDType(string key, out Label value)
        {
            if (!IdToTypeCache.TryGetValue(key, out value))
            {
                value = Label.Base;
                return false;
            }
            else
            {
                return true;
            }
        }

        internal static bool GetChildObjects(string dn, out TypedPrincipal[] childObjects)
        {
            childObjects = new TypedPrincipal[] { };
            var matchingKeysAll = ValueToIdCache.Where(kvp => kvp.Key.Contains(dn)).Select(kvp => kvp.Key);
            var matchingKeys = matchingKeysAll.Where(key => key != dn).ToList();


            
            foreach (string matchingKey in matchingKeys)
            {
                if (IsDistinguishedNameFiltered(matchingKey))
                    continue;
               
                TypedPrincipal childObject = new TypedPrincipal { };
                if (GetConvertedValue(matchingKey, out var id) && GetIDType(id, out var type))
                {
                    childObject = new TypedPrincipal
                    {
                        ObjectIdentifier = id.ToUpper(),
                        ObjectType = type
                    };
                    childObjects = childObjects.Append(childObject).ToArray();
                }
                else
                    continue;
            }

            if (matchingKeys == null)
            {
                return false;
            }
            else
            {
                return true;
            }
        }


        internal static bool GetDomainChildObjects(string dn, out TypedPrincipal[] childObjects)
        {
            int dnlevel = dn.Count(f => f == '=');
            childObjects = new TypedPrincipal[] { };
            var matchingKeysAll = ValueToIdCache.Where(kvp => kvp.Key.Contains(dn)).Select(kvp => kvp.Key);
            var matchingKeys = matchingKeysAll.Where(key => key != dn).ToList();



            foreach (string matchingKey in matchingKeys)
            {
                //Getting one sublevel of data for the domain child objects
                if (matchingKey.Count(f => f == '=') != (dnlevel + 1))
                    continue;

                if (IsDistinguishedNameFiltered(matchingKey))
                    continue;

                TypedPrincipal childObject = new TypedPrincipal { };
                if (GetConvertedValue(matchingKey, out var id) && GetIDType(id, out var type))
                {
                    childObject = new TypedPrincipal
                    {
                        ObjectIdentifier = id.ToUpper(),
                        ObjectType = type
                    };
                    childObjects = childObjects.Append(childObject).ToArray();
                }
                else
                    continue;
            }

            if (matchingKeys == null)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        private static bool IsDistinguishedNameFiltered(string distinguishedName)
        {
            var dn = distinguishedName.ToUpper();
            if (dn.Contains("CN=PROGRAM DATA,DC=")) return true;

            if (dn.Contains("CN=SYSTEM,DC=")) return true;

            return false;
        }

        private static string GetPrefixKey(string key, string domain)
        {
            return $"{key}|{domain}";
        }
        public static string GetCacheStats()
        {
            try
            {
                return
                    $"{IdToTypeCache.Count} ID to type mappings.\n {ValueToIdCache.Count} name to SID mappings.\n";
            }
            catch
            {
                return "";
            }
        }



    }
}