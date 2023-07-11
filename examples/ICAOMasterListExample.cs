using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using ePassport;

namespace examples
{
    class ICAOMasterListExample
    {
        static void displayCertInfo(Certificate cert)
        {
            Dictionary<string, string> certDict = CertificateExample.GetSomeHumanReadableInfo(cert);
            foreach (string key in certDict.Keys)
            {
                Console.WriteLine("\t\t" + key + " = " + certDict[key]);
            }
        }

        public static IEnumerable<SubjectPublicKeyInfo> ParseUrlAsync(List<string> certUrls)
        {
            Console.WriteLine("Parsing ICAO Masterlist from URLs");

            foreach (string c in certUrls) {

            using (WebClient client = new WebClient())
            {
                byte[] data = client.DownloadData(c);
                /*{
                    byte[] data = await client.GetByteArrayAsync(certUrl);*/
                    ePassport.Certificate certificate = Utils.DerDecode<ePassport.Certificate>(data);
                    // The variable 'data' now contains the file data as a byte array.
                    // You can use this byte array as needed in your application.
                    displayCertInfo(certificate);
                    yield return certificate.TbsCertificate.SubjectPublicKeyInfo;
                }
            }
        }


        public static IEnumerable<SubjectPublicKeyInfo> Parse(string filename)
        {
            Console.WriteLine("Parsing ICAO Masterlist: {0}", filename);

            if (filename == null)
            {
                Console.WriteLine("\tdownload the CSCA masterlist file from : {0}", @"https://www.icao.int/Security/FAL/PKD/Pages/icao-master-list.aspx");
                Console.WriteLine("\tand add reference to file");
                yield break;
            }

            using (FileStream fs = File.Open(filename, FileMode.Open))
            {
                byte[] data = new byte[fs.Length];
                fs.Read(data, 0, data.Length);

                ContentInfo contentInfo = Utils.DerDecode<ContentInfo>(data);

                KnownOids oid = Oids.ParseKnown(contentInfo.ContentType.Value.Value);
                if (oid == KnownOids.signedData)
                {
                    SignedData signedData = Utils.DerDecode<SignedData>(contentInfo.Content);

                    // check if SignedData contains a cscaMasterList object
                    if (Oids.ParseKnown(signedData.EncapContentInfo.EContentType.Value.Value) == KnownOids.cscaMasterList)
                    {
                        // check the masterlist digest signature here
                        // check the digest signature
                        Certificate cscaMasterListcertificate;

                        if (CryptoUtils.VerifySignedData(signedData, out cscaMasterListcertificate) == true)
                        {
                            Console.WriteLine("\tCSCA masterlist digest signature verified successfully using cert :");
                            displayCertInfo(cscaMasterListcertificate);
                            
                            // now obtain the master list content
                            CscaMasterList cscaMasterList = Utils.DerDecode<CscaMasterList>(signedData.EncapContentInfo.EContent);

                            Console.WriteLine("\tnumber of certs present in cscaMasterList : " + cscaMasterList.CertList.Count);

                            int idx = 0;
                            foreach (Certificate certificate in cscaMasterList.CertList) {
                                Console.WriteLine("\tCertificate[{0} / {1}]:", idx, certificate.TbsCertificate.SerialNumber.Value);
                                yield return certificate.TbsCertificate.SubjectPublicKeyInfo;
                                displayCertInfo(certificate);
                                idx++;
                            }
                        }
                        else
                        {
                            Console.WriteLine("\tERROR : CSCA masterlist digest signature verification failed");
                        }                        
                    }
                }

            }
        }

        public static IEnumerable<string> ParseLDIFUrlAsync(List<string> certUrls, List<ePassport.SubjectPublicKeyInfo> certs)
        {
            Console.WriteLine("Parsing PKD/CRL from URLs");

            foreach (string c in certUrls)
            {

                using (WebClient client = new WebClient())
                {
                    byte[] data = client.DownloadData(c);
                    IEnumerable<string> i = CryptoUtils.GeRevokedSerialNumbersFromCrl(data, certs);
                    foreach (string s in i)
                    {
                        yield return s;
                    }
                }
            }
        }

        public static IEnumerable<string> ParseLDIF(string filename, List<ePassport.SubjectPublicKeyInfo> certs)
        {
            List<string> crlValues = new List<string>();
            string currentValue = null;
            Console.WriteLine("Parsing ICAO ldif PKD: {0}", filename);
            using (StreamReader reader = new StreamReader(filename))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    // If the line starts with a space, it's a continuation of the current value.
                    if (line.StartsWith(" "))
                    {
                        if (currentValue != null)
                        {
                            // Append the line to the current value, removing the leading space.
                            currentValue += line.Substring(1);
                        }
                        continue;
                    }

                    // If we have a current value, it's now complete.
                    if (currentValue != null)
                    {
                        crlValues.Add(currentValue);
                        currentValue = null;
                    }

                    // Look for 'certificateRevocationList;binary::' in the line.
                    if (line.StartsWith("certificateRevocationList;binary::"))
                    {
                        // Start a new current value.
                        currentValue = line.Substring("certificateRevocationList;binary::".Length);
                    }
                }

                // If we have a current value at the end of the file, it's now complete.
                if (currentValue != null)
                {
                    crlValues.Add(currentValue);
                }
            }

            var j = 1; var jj = 1;
            foreach (string entry in crlValues) {
                byte[] crlData = Convert.FromBase64String(entry);
                Console.WriteLine("PKD CRL: {0}", j);
                foreach (var val in CryptoUtils.GeRevokedSerialNumbersFromCrl(crlData, certs))
                {
                    Console.WriteLine(" - sub: {0}", val);
                    yield return val;
                }
                j++;
            }

        }
    }
}
