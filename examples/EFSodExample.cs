using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using ePassport;
using System.Linq;
using System.Security.Cryptography;


namespace examples
{
    class EFSodExample
    {
        static void displayCertInfo(Certificate cert)
        {
            Dictionary<string, string> certDict = CertificateExample.GetSomeHumanReadableInfo(cert);
            foreach (string key in certDict.Keys)
            {
                Console.WriteLine("\t\t" + key + " = " + certDict[key]);
            }
        }

        public static void Parse(string filename, List<SubjectPublicKeyInfo> certs)
        {
            Console.WriteLine("Parsing Document Security Object (EF.SOD): {0}", filename);

            using (FileStream fs = File.Open(filename, FileMode.Open))
            {
                byte[] data = new byte[fs.Length];
                fs.Read(data, 0, data.Length);

                EFSOD efSod = Utils.DerDecode<EFSOD>(data);

                // check if SignedData contains an LdsSecurityObject
                KnownOids eContentTypeOidEnum = Oids.ParseKnown(efSod.Value.Sod.SignedData.EncapContentInfo.EContentType.Value.Value);
                if ((eContentTypeOidEnum == KnownOids.ldsSecurityObject) || (eContentTypeOidEnum == KnownOids.ldsSecurityObject_alt))
                {
                       LDSSecurityObject securityObject = Utils.DerDecode<LDSSecurityObject>(efSod.Value.Sod.SignedData.EncapContentInfo.EContent);
                        var hashes = securityObject.DataGroupHashValues;
                        var digestAlgorithmOid = securityObject.HashAlgorithm.Value.Algorithm.Value;

                    /*foreach (var hash in hashes)
                    {
                        var key = hash.DataGroupNumber.Value - 2; //todo is it DG1 - 1 ??
                        h.Add((DGName)key, hash.DataG1.3.14.3.2.26roupHashValue);
                    }

                    if (digestAlgorithmOid == null)
                    {
                        throw new ApplicationException("Unable to find hash algorithm used");
                    }

                    if (h.Count == 0)
                    {
                        throw new ApplicationException("Unable to extract hashes");
                    }*/


                    try
                    {
                        if (CryptoUtils.VerifySignedData(efSod.Value.Sod.SignedData) == true)
                        {
                            Console.WriteLine("\tpassport content-digest signature is consistent");
                            //return;
                        }

                        if (CryptoUtils.VerifySignedData(efSod.Value.Sod.SignedData, out Certificate cert) == true)
                        {
                            displayCertInfo(cert);
                            int j = 1;
                            foreach (var certEntry in certs)
                            {
                                CertificateExample.Decode(Utils.DerEncodeAsByteArray<Certificate>(cert));
                                CertificateExample.Encode(Utils.DerEncodeAsByteArray<Certificate>(cert));

                                byte[] signature = cert.Signature.Value; 
                                var algorithm = cert.SignatureAlgorithm.Algorithm.Value;
                                byte[] certificate = Utils.DerEncodeAsByteArray<TBSCertificate>(cert.TbsCertificate);

                                Console.WriteLine(j);
                                var i = CryptoUtils.VerifySignature(certEntry, certificate, cert.SignatureAlgorithm, signature);
                                j++;
                                if (i)
                                {
                                    Console.WriteLine("WTF");
                                }                                

                                //if (certEntry.SubjectPublicKey == cert.Signature)
                            }
                            //if (certs.OrderBy(c=>c).ToList().Contains(cert.TbsCertificate.SerialNumber.Value.ToString()))
                            Console.WriteLine("\tA");
                            return;
                        }

                        Console.WriteLine("\tERROR : passport content-digest signature verification failed");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("\tERROR : {0}", e.Message);
                    }                    
                }
                else
                {
                    Console.WriteLine("\tERROR : LDS Security object not found !");
                }

            }            
        }
    }
}
