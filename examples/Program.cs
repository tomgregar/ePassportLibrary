using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static System.Net.WebRequestMethods;

namespace examples
{
    
    class Program
    {

        public static void Main(string[] args)
        {
            // example using LetsEncrypt Self-Signed certificate - see https://letsencrypt.org/certificates/
            CertificateExample.Decode(@"isrgrootx1.der");

            // example using LetsEncrypt Cross-signed certificate - see https://letsencrypt.org/certificates/
            CertificateExample.Decode(@"isrg-root-x1-cross-signed.der");

            // example of parsing of the ICAO masterlist
            // see https://www.icao.int/Security/FAL/PKD/Pages/icao-master-list.aspx to obtain the file
            List<ePassport.SubjectPublicKeyInfo> certs = ICAOMasterListExample.ParseUrlAsync(new List<string> {
                /*"https://www.mvcr.cz/soubor/cze-csca-20210323-cer.aspx","https://www.mvcr.cz/soubor/cze-eid-csca-20180618-cer.aspx","https://www.mvcr.cz/soubor/cze-eid-csca-test-20180518-cer.aspx","https://www.mvcr.cz/soubor/cze-csca-20160324-cer.aspx","https://www.mvcr.cz/soubor/cze-csca-test-20060720-cer.aspx","https://www.mvcr.cz/soubor/cze-csca-20110325-cer.aspx","https://www.mvcr.cz/soubor/cze-csca-20090113-der.aspx","https://www.mvcr.cz/soubor/cze-csca-20110325-cer.aspx",*/ "https://www.eid.hr/datastore/filestore/10/akdcaroot.crt"

            }).ToList(); //"20230524_DEMasterList.ml"

            List<string> ignore = ICAOMasterListExample.ParseLDIFUrlAsync(new List<string> { "https://www.mvcr.cz/soubor/cze-eid-csca-crl-crl.aspx", "https://www.mvcr.cz/soubor/cze-eid-csca-crl-test-crl.aspx", "https://www.mvcr.cz/soubor/cze-csca-crl-crl.aspx", "https://www.mvcr.cz/soubor/cze-csca-crl-test-crl.aspx", "http://crl1.eid.hr/hridca.crl" }, certs).ToList();

            //"icaopkd-001-dsccrl-006699.ldif"

            try
            {
                // Write the strings to the file
                System.IO.File.WriteAllLines("f:/pkd-sn-to-ignore.txt", ignore);
                Console.WriteLine("List of strings saved to file successfully.");
            }
            catch (Exception ex)
            {
                // Handle any exceptions that occur during the file write process
                Console.WriteLine("Error saving list to file: " + ex.Message);
            }

            // Parsing example of an ePassport EF.COM (Common data elements) 
            EFComExample.Parse(@"bsi2008\EF_COM.bin");

            // Parsing example of an ePassport EF.SOD (Document Security Object) 
            EFSodExample.Parse(@"bsi2008\sod2.data", certs, ignore);
            //EFSodExample.Parse(@"bsi2008\EF_SOD.data", certs);

            // Parsing example of an ePassport Datagroup1 (mrz) 
            MrzDatagroupExample.Parse(@"bsi2008\Datagroup1.bin");

            // Parsing example of an ePassport Datagroup2 (face) 
            FaceDatagroupExample.Parse(@"bsi2008\Datagroup2.bin");

            // Parsing example of an ePassport Datagroup3 (fingerprint)
            FingerPrintDatagroupExample.Parse(@"bsi2008\Datagroup3.bin");

            // Parsing example of an ePassport Datagroup4 (iris)
            IrisDatagroupExample.Parse(@"bsi2008\Datagroup4.bin");

            // Parsing example of an ePassport Datagroup14 (security options)
            SecurityOptionsDatagroupExample.Parse(@"bsi2008\Datagroup14.bin");

            // Parsing example of an ePassport Datagroup15 (Active Authentication Public Key)
            ActiveAuthenticationDatagroupExample.Parse(@"bsi2008\Datagroup15.bin");
        }

        
    }
}
