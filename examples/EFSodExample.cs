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

        public static bool Parse(string filename, List<SubjectPublicKeyInfo> certs, List<string> toIgnore)
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
                        bool isOk = false;
                        if (CryptoUtils.VerifySignedData(efSod.Value.Sod.SignedData, out Certificate cert) == true)
                        {
                            Console.WriteLine("\tpassport content-digest signature is consistent");
                            displayCertInfo(cert);
                            int j = 1;
                            foreach (var certEntry in certs)
                            {
                                //CertificateExample.Decode(Utils.DerEncodeAsByteArray<Certificate>(cert));
                                //CertificateExample.Encode(Utils.DerEncodeAsByteArray<Certificate>(cert));

                                byte[] signature = cert.Signature.Value;
                                var signatureAlgorithm = cert.SignatureAlgorithm.Algorithm.Value;
                                byte[] tbscertificate = Utils.DerEncodeAsByteArray<Certificate>(cert);
                                byte[] certEntryBytes = Utils.DerEncodeAsByteArray<SubjectPublicKeyInfo>(certEntry);

                                Console.WriteLine(j);
                                Console.WriteLine(certEntry.Algorithm.Algorithm.Value);

                                //var i = CryptoUtils.VerifySignatureV2(certEntry, tbscertificate, signatureAlgorithm, signature);
                                var i = CryptoUtils.CheckSignature(tbscertificate, certEntryBytes);
                                Console.WriteLine(i);
                                j++;

                                if (i)
                                {
                                    Console.WriteLine("!!!!!!!!!!!!!!!!!!!!!!!WTF!!!!!!!!!!!!!!!!!!!!!!");
                                    isOk = true;
                                }

                                //if (certEntry.SubjectPublicKey == cert.Signature)
                            }

                            if (toIgnore.Contains(cert.TbsCertificate.SerialNumber.Value.ToString()))
                            {
                                isOk = false;
                            }
                            return isOk;
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
                return false;
            }            
        }
    }
}
