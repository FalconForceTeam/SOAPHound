using System;
using System.Runtime.InteropServices;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace SOAPHound
{
    class hDNSRecord
    {
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a
        [StructLayout(LayoutKind.Sequential)]
        public struct DnssrvRpcRecord
        {
            public UInt16 wDataLength;
            public UInt16 wType;
            public UInt32 dwFlags;
            public UInt32 dwSerial;
            public UInt32 dwTtlSeconds;
            public UInt32 dwTimeStamp;
            public UInt32 dwReserved;
        }

        public static void ReadDNSObject(Byte[] arrObj)
        {
            try
            {
                IntPtr pObject = Marshal.AllocHGlobal(arrObj.Length);
                Marshal.Copy(arrObj, 0, pObject, arrObj.Length);

                DnssrvRpcRecord oRecord = (DnssrvRpcRecord)Marshal.PtrToStructure(pObject, typeof(DnssrvRpcRecord));
                IntPtr pData = (IntPtr)(pObject.ToInt64() + 24);

                if (oRecord.wType == 0)
                {
                    Int64 iMSTS = (Marshal.ReadInt64(pData) / 10) / 1000;
                    Console.WriteLine("    |_ DNS_RPC_RECORD_TS : " + (new DateTime(1601, 1, 1)).AddMilliseconds(iMSTS));
                }
                else if (oRecord.wType == 1)
                {
                    byte[] bytes = BitConverter.GetBytes(Marshal.ReadInt32(pData));
                    Console.WriteLine("    |_ DNS_RPC_RECORD_A : " + new IPAddress(bytes).ToString());
                }
                else if (oRecord.wType == 2 || oRecord.wType == 5 || oRecord.wType == 12)
                {
                    Int16 iLen = Marshal.ReadByte(pData);
                    Int16 iSeg = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 1));
                    IntPtr pDataPtr = (IntPtr)(pData.ToInt64() + 2);
                    String sRecord = String.Empty;
                    for (int i = 0; i < iSeg; i++)
                    {
                        Int16 iSegLen = Marshal.ReadByte(pDataPtr);
                        sRecord += Marshal.PtrToStringAnsi((IntPtr)(pDataPtr.ToInt64() + 1), iSegLen);
                        if (i != (iSeg - 1))
                        {
                            sRecord += ".";
                        }
                        pDataPtr = (IntPtr)(pDataPtr.ToInt64() + iSegLen + 1);
                    }
                    Console.WriteLine("    |_ DNS_RPC_RECORD_NODE_NAME : " + sRecord);
                }
                else if (oRecord.wType == 33)
                {
                    Int16 iPrio = getInt16ToBigEndian(Marshal.ReadInt16(pData));
                    Int16 iWeight = getInt16ToBigEndian(Marshal.ReadInt16((IntPtr)(pData.ToInt64() + 2)));
                    Int16 iPort = getInt16ToBigEndian(Marshal.ReadInt16((IntPtr)(pData.ToInt64() + 4)));
                    Int16 iSeg = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 7));
                    IntPtr pDataPtr = (IntPtr)(pData.ToInt64() + 8);
                    String sRecord = String.Empty;
                    for (int i = 0; i < iSeg; i++)
                    {
                        Int16 iSegLen = Marshal.ReadByte(pDataPtr);
                        sRecord += Marshal.PtrToStringAnsi((IntPtr)(pDataPtr.ToInt64() + 1), iSegLen);
                        if (i != (iSeg - 1))
                        {
                            sRecord += ".";
                        }
                        pDataPtr = (IntPtr)(pDataPtr.ToInt64() + iSegLen + 1);
                    }
                    Console.WriteLine("    |_ DNS_RPC_RECORD_SRV");
                    Console.WriteLine("       |_ Priority : " + iPrio);
                    Console.WriteLine("       |_ Weight   : " + iWeight);
                    Console.WriteLine("       |_ Port     : " + iPort);
                    Console.WriteLine("       |_ Name     : " + sRecord);
                }
                else if (oRecord.wType == 6)
                {
                    Int32 iSerial = getInt32ToBigEndian(Marshal.ReadInt32(pData));
                    Int32 iRefresh = getInt32ToBigEndian(Marshal.ReadInt32((IntPtr)(pData.ToInt64() + 4)));
                    Int32 iRetry = getInt32ToBigEndian(Marshal.ReadInt32((IntPtr)(pData.ToInt64() + 8)));
                    Int32 iExpire = getInt32ToBigEndian(Marshal.ReadInt32((IntPtr)(pData.ToInt64() + 12)));
                    Int32 iMinimumTtl = getInt32ToBigEndian(Marshal.ReadInt32((IntPtr)(pData.ToInt64() + 16)));

                    Int16 iLen = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 20));
                    Int16 iSeg = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 21));
                    IntPtr pDataPtr = (IntPtr)(pData.ToInt64() + 22);
                    String sNamePrimaryServer = String.Empty;
                    for (int i = 0; i < iSeg; i++)
                    {
                        Int16 iSegLen = Marshal.ReadByte(pDataPtr);
                        sNamePrimaryServer += Marshal.PtrToStringAnsi((IntPtr)(pDataPtr.ToInt64() + 1), iSegLen);
                        if (i != (iSeg - 1))
                        {
                            sNamePrimaryServer += ".";
                        }
                        pDataPtr = (IntPtr)(pDataPtr.ToInt64() + iSegLen + 1);
                    }

                    iSeg = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 21 + iLen));
                    pDataPtr = (IntPtr)(pData.ToInt64() + 22 + iLen);
                    String sZoneAdminEmail = String.Empty;
                    for (int i = 0; i < iSeg; i++)
                    {
                        Int16 iSegLen = Marshal.ReadByte(pDataPtr);
                        sZoneAdminEmail += Marshal.PtrToStringAnsi((IntPtr)(pDataPtr.ToInt64() + 1), iSegLen);
                        if (i != (iSeg - 1))
                        {
                            sZoneAdminEmail += ".";
                        }
                        pDataPtr = (IntPtr)(pDataPtr.ToInt64() + iSegLen + 1);
                    }

                    Console.WriteLine("    |_ DNS_RPC_RECORD_SOA");
                    Console.WriteLine("       |_ SerialNo      : " + iSerial);
                    Console.WriteLine("       |_ Refresh       : " + iRefresh);
                    Console.WriteLine("       |_ Retry         : " + iRetry);
                    Console.WriteLine("       |_ Expire        : " + iExpire);
                    Console.WriteLine("       |_ MinimumTtl    : " + iMinimumTtl);
                    Console.WriteLine("       |_ PrimaryServer : " + sNamePrimaryServer);
                    Console.WriteLine("       |_ AdminEmail    : " + sZoneAdminEmail);
                }
                else if (oRecord.wType == 28)
                {
                    Byte[] bIPV6 = new byte[16];
                    Marshal.Copy(pData, bIPV6, 0, 16);
                    Console.WriteLine("    |_ DNS_RPC_RECORD_AAAA : " + new IPAddress(bIPV6).ToString());
                }
                else
                {
                    Console.WriteLine("    |_ Unimplemented DNS Record Type ---> " + oRecord.wType);
                    Console.WriteLine("       |_ DEBUG : " + BitConverter.ToString(arrObj).Replace("-", " "));
                }

                Marshal.FreeHGlobal(pObject);
            }
            catch (Exception ex)
            {
                Console.WriteLine("    |_ Failed to parse DNS entry..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("       |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("       |_ " + ex.Message);
                }
            }
        }

        public static void ReadandOutputDNSObject(Byte[] arrObj, string filepath)
        {
            try
            {
                IntPtr pObject = Marshal.AllocHGlobal(arrObj.Length);
                Marshal.Copy(arrObj, 0, pObject, arrObj.Length);

                DnssrvRpcRecord oRecord = (DnssrvRpcRecord)Marshal.PtrToStructure(pObject, typeof(DnssrvRpcRecord));
                IntPtr pData = (IntPtr)(pObject.ToInt64() + 24);

                if (oRecord.wType == 0)
                {
                    Int64 iMSTS = (Marshal.ReadInt64(pData) / 10) / 1000;
                    File.AppendAllText(filepath, "\r\n    |_ DNS_RPC_RECORD_TS : " + (new DateTime(1601, 1, 1)).AddMilliseconds(iMSTS));
                }
                else if (oRecord.wType == 1)
                {
                    byte[] bytes = BitConverter.GetBytes(Marshal.ReadInt32(pData));
                    File.AppendAllText(filepath, "\r\n    |_ DNS_RPC_RECORD_A : " + new IPAddress(bytes).ToString());
                }
                else if (oRecord.wType == 2 || oRecord.wType == 5 || oRecord.wType == 12)
                {
                    Int16 iLen = Marshal.ReadByte(pData);
                    Int16 iSeg = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 1));
                    IntPtr pDataPtr = (IntPtr)(pData.ToInt64() + 2);
                    String sRecord = String.Empty;
                    for (int i = 0; i < iSeg; i++)
                    {
                        Int16 iSegLen = Marshal.ReadByte(pDataPtr);
                        sRecord += Marshal.PtrToStringAnsi((IntPtr)(pDataPtr.ToInt64() + 1), iSegLen);
                        if (i != (iSeg - 1))
                        {
                            sRecord += ".";
                        }
                        pDataPtr = (IntPtr)(pDataPtr.ToInt64() + iSegLen + 1);
                    }
                    File.AppendAllText(filepath, "\r\n    |_ DNS_RPC_RECORD_NODE_NAME : " + sRecord);
                }
                else if (oRecord.wType == 33)
                {
                    Int16 iPrio = getInt16ToBigEndian(Marshal.ReadInt16(pData));
                    Int16 iWeight = getInt16ToBigEndian(Marshal.ReadInt16((IntPtr)(pData.ToInt64() + 2)));
                    Int16 iPort = getInt16ToBigEndian(Marshal.ReadInt16((IntPtr)(pData.ToInt64() + 4)));
                    Int16 iSeg = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 7));
                    IntPtr pDataPtr = (IntPtr)(pData.ToInt64() + 8);
                    String sRecord = String.Empty;
                    for (int i = 0; i < iSeg; i++)
                    {
                        Int16 iSegLen = Marshal.ReadByte(pDataPtr);
                        sRecord += Marshal.PtrToStringAnsi((IntPtr)(pDataPtr.ToInt64() + 1), iSegLen);
                        if (i != (iSeg - 1))
                        {
                            sRecord += ".";
                        }
                        pDataPtr = (IntPtr)(pDataPtr.ToInt64() + iSegLen + 1);
                    }
                    File.AppendAllText(filepath, "\r\n    |_ DNS_RPC_RECORD_SRV");
                    File.AppendAllText(filepath, "\r\n       |_ Priority : " + iPrio);
                    File.AppendAllText(filepath, "\r\n       |_ Weight   : " + iWeight);
                    File.AppendAllText(filepath, "\r\n       |_ Port     : " + iPort);
                    File.AppendAllText(filepath, "\r\n       |_ Name     : " + sRecord);
                }
                else if (oRecord.wType == 6)
                {
                    Int32 iSerial = getInt32ToBigEndian(Marshal.ReadInt32(pData));
                    Int32 iRefresh = getInt32ToBigEndian(Marshal.ReadInt32((IntPtr)(pData.ToInt64() + 4)));
                    Int32 iRetry = getInt32ToBigEndian(Marshal.ReadInt32((IntPtr)(pData.ToInt64() + 8)));
                    Int32 iExpire = getInt32ToBigEndian(Marshal.ReadInt32((IntPtr)(pData.ToInt64() + 12)));
                    Int32 iMinimumTtl = getInt32ToBigEndian(Marshal.ReadInt32((IntPtr)(pData.ToInt64() + 16)));

                    Int16 iLen = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 20));
                    Int16 iSeg = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 21));
                    IntPtr pDataPtr = (IntPtr)(pData.ToInt64() + 22);
                    String sNamePrimaryServer = String.Empty;
                    for (int i = 0; i < iSeg; i++)
                    {
                        Int16 iSegLen = Marshal.ReadByte(pDataPtr);
                        sNamePrimaryServer += Marshal.PtrToStringAnsi((IntPtr)(pDataPtr.ToInt64() + 1), iSegLen);
                        if (i != (iSeg - 1))
                        {
                            sNamePrimaryServer += ".";
                        }
                        pDataPtr = (IntPtr)(pDataPtr.ToInt64() + iSegLen + 1);
                    }

                    iSeg = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 21 + iLen));
                    pDataPtr = (IntPtr)(pData.ToInt64() + 22 + iLen);
                    String sZoneAdminEmail = String.Empty;
                    for (int i = 0; i < iSeg; i++)
                    {
                        Int16 iSegLen = Marshal.ReadByte(pDataPtr);
                        sZoneAdminEmail += Marshal.PtrToStringAnsi((IntPtr)(pDataPtr.ToInt64() + 1), iSegLen);
                        if (i != (iSeg - 1))
                        {
                            sZoneAdminEmail += ".";
                        }
                        pDataPtr = (IntPtr)(pDataPtr.ToInt64() + iSegLen + 1);
                    }

                    File.AppendAllText(filepath, "\r\n    |_ DNS_RPC_RECORD_SOA");
                    File.AppendAllText(filepath, "\r\n       |_ SerialNo      : " + iSerial);
                    File.AppendAllText(filepath, "\r\n       |_ Refresh       : " + iRefresh);
                    File.AppendAllText(filepath, "\r\n       |_ Retry         : " + iRetry);
                    File.AppendAllText(filepath, "\r\n       |_ Expire        : " + iExpire);
                    File.AppendAllText(filepath, "\r\n       |_ MinimumTtl    : " + iMinimumTtl);
                    File.AppendAllText(filepath, "\r\n       |_ PrimaryServer : " + sNamePrimaryServer);
                    File.AppendAllText(filepath, "\r\n       |_ AdminEmail    : " + sZoneAdminEmail);
                }
                else if (oRecord.wType == 28)
                {
                    Byte[] bIPV6 = new byte[16];
                    Marshal.Copy(pData, bIPV6, 0, 16);
                    File.AppendAllText(filepath, "\r\n    |_ DNS_RPC_RECORD_AAAA : " + new IPAddress(bIPV6).ToString());
                }
                else
                {
                    File.AppendAllText(filepath, "\r\n    |_ Unimplemented DNS Record Type ---> " + oRecord.wType);
                    File.AppendAllText(filepath, "\r\n       |_ DEBUG : " + BitConverter.ToString(arrObj).Replace("-", " "));
                }

                Marshal.FreeHGlobal(pObject);
            }
            catch (Exception ex)
            {
                File.AppendAllText(filepath, "\r\n    |_ Failed to parse DNS entry..");
                if (ex.InnerException != null)
                {
                    File.AppendAllText(filepath, "\r\n       |_ " + ex.InnerException.Message);
                }
                else
                {
                    File.AppendAllText(filepath, "\r\n       |_ " + ex.Message);
                }
            }
        }
        public static Int16 getInt16ToBigEndian(Int16 iInput)
        {
            byte[] aBytes = BitConverter.GetBytes(iInput);
            Array.Reverse(aBytes);
            return BitConverter.ToInt16(aBytes, 0);
        }

        public static Int32 getInt32ToBigEndian(Int32 iInput)
        {
            byte[] aBytes = BitConverter.GetBytes(iInput);
            Array.Reverse(aBytes);
            return BitConverter.ToInt32(aBytes, 0);
        }
    }
}
