

using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;


namespace ePassport
{
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Crypto.Engines;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Crypto.Signers;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Crypto.Tls;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.TeleTrust;
    using Org.BouncyCastle.Asn1.X9;
    using Org.BouncyCastle.Asn1.Esf;
    using Org.BouncyCastle.Asn1.Ocsp;
    using Org.BouncyCastle.Cms;
    using Org.BouncyCastle.X509;
    using Org.BouncyCastle.X509;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Crypto;
    using System.Linq;
    using System.Runtime.ConstrainedExecution;

    public static class CryptoUtils
    {
        public static int GetHashAlgoOutputSizeFromOid(string algorithmOid)
        {
            KnownOids algorithmOidEnum = Oids.ParseKnown(algorithmOid);

            switch (algorithmOidEnum)
            {
                case KnownOids.sha1:
                case KnownOids.ecdsa_with_sha1:
                    return (160 / 8);

                case KnownOids.sha256:
                    return (256 / 8);                    

                case KnownOids.sha384:
                    return (384 / 8);                    

                case KnownOids.sha512:
                    return (512 / 8);                


                default:
                    throw new NotImplementedException("hash algorithm : " + algorithmOidEnum + "(" + algorithmOid + ") not yet implemented");
            }
        }

        private static IDigest GetBouncyCastleHashAlgoInstanceFromOid(string algorithmOid)
        {
            GeneralDigest digestAlgo = new Sha1Digest();

            KnownOids algorithmOidEnum = Oids.ParseKnown(algorithmOid);            

            switch (algorithmOidEnum)
            {
                case KnownOids.sha1:
                case KnownOids.ecdsa_with_sha1:
                    return new Sha1Digest();

                case KnownOids.sha256:
                    return new Sha256Digest();

                case KnownOids.sha384:
                    return new Sha384Digest();

                case KnownOids.sha512:
                    return new Sha512Digest();

                default:
                    throw new NotImplementedException("hash algorithm : " + algorithmOidEnum + "(" + algorithmOid + ") not yet implemented");
            }
        }

        private static IDigest GetBouncyCastleHashAlgoInstanceFromLength(int length)
        {
            GeneralDigest digestAlgo = new Sha1Digest();

            switch (length)
            {
                case 512: return new Sha512Digest();
                case 384: return new Sha384Digest();
                case 256: return new Sha256Digest();
                default: return new Sha1Digest();               
            }
        }

        private static System.Security.Cryptography.HashAlgorithm GetMicrosoftHashAlgoInstanceFromOid(string algorithmOid)
        {
            KnownOids algorithmOidEnum = Oids.ParseKnown(algorithmOid);

            switch (algorithmOidEnum)
            {
                case KnownOids.sha1:
                case KnownOids.ecdsa_with_sha1:
                    return SHA1.Create();                    

                case KnownOids.sha256:
                    return SHA256.Create();

                case KnownOids.sha384:
                    return SHA384.Create();                    

                case KnownOids.sha512:
                    return SHA512.Create();                    

                default:
                    throw new NotImplementedException("hash algorithm : " + algorithmOidEnum + "(" + algorithmOid + ") not yet implemented");
            }
        }

        public static byte[] ComputeHash(string algorithmOid, byte[] data)
        {
            System.Security.Cryptography.HashAlgorithm hashAlgo = null;
            try
            {
                hashAlgo = GetMicrosoftHashAlgoInstanceFromOid(algorithmOid);
                return hashAlgo.ComputeHash(data);
            }
            finally
            {
                if (hashAlgo != null)
                {
                    hashAlgo.Dispose();
                }
            }            
        }

        public static bool VerifySignature(SubjectPublicKeyInfo subjectPublicKeyInfo, byte[] dataForSignature, AlgorithmIdentifier signatureAlgorithm, byte[] signatureToVerify)
        {
            bool result = false;

            KnownOids publicKeyOidEnum = Oids.ParseKnown(subjectPublicKeyInfo.Algorithm.Algorithm.Value);
            KnownOids AlgorithmOidEnum = Oids.ParseKnown(signatureAlgorithm.Algorithm.Value);
            switch (publicKeyOidEnum)
            {
                case KnownOids.rsaEncryption:
                    {
                        if (AlgorithmOidEnum == KnownOids.ecdsa_with_sha1 || AlgorithmOidEnum == KnownOids.ecdsa_with_sha256 || AlgorithmOidEnum == KnownOids.ecdsa_with_sha384 || AlgorithmOidEnum == KnownOids.ecdsa_with_sha512)
                        {
                            //incompatible public keys
                            return false;
                        }
                        RSAPublicKey rsaPublicKey = Utils.DerDecode<RSAPublicKey>(subjectPublicKeyInfo.SubjectPublicKey.Value);

                        byte[] modulus = rsaPublicKey.Modulus.ToMicrosoftBigEndianByteArray();
                        byte[] exponent = rsaPublicKey.PublicExponent.ToMicrosoftBigEndianByteArray();

                        //Create a new instance of RSACryptoServiceProvider.
                        using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(modulus.Length * 8))
                        {
                            //Create a new instance of RSAParameters.
                            RSAParameters RSAKeyInfo = new RSAParameters();

                            //Set RSAKeyInfo to the public key values.                             
                            RSAKeyInfo.Modulus = modulus;
                            RSAKeyInfo.Exponent = exponent;

                            //Import key parameters into RSA.
                            RSA.ImportParameters(RSAKeyInfo);

                            result = RSA.VerifyData(dataForSignature, signatureAlgorithm.Algorithm.Value, signatureToVerify);
                        }
                    }
                    return result;


                case KnownOids.rsassa_pss:
                    {
                        if (AlgorithmOidEnum == KnownOids.ecdsa_with_sha1 || AlgorithmOidEnum == KnownOids.ecdsa_with_sha256 || AlgorithmOidEnum == KnownOids.ecdsa_with_sha384 || AlgorithmOidEnum == KnownOids.ecdsa_with_sha512)
                        {
                            //incompatible public keys
                            return false;
                        }
                        RSAPublicKey rsaPublicKey = Utils.DerDecode<RSAPublicKey>(subjectPublicKeyInfo.SubjectPublicKey.Value);

                        int saltLength = 20;
                        IDigest digestAlgo = new Sha1Digest();

                        if (signatureAlgorithm.isParametersPresent())
                        {
                            RSASSA_PSS_params rsassa_pss_params = Utils.DerDecode<RSASSA_PSS_params>(signatureAlgorithm.Parameters);
                            digestAlgo = GetBouncyCastleHashAlgoInstanceFromOid(rsassa_pss_params.HashAlgorithm.Value.Algorithm.Value);
                            saltLength = (int)rsassa_pss_params.SaltLength;
                        }

                        RsaKeyParameters publickey = new RsaKeyParameters(
                            false,
                            rsaPublicKey.Modulus.ToBouncyCastleBigInteger(),
                            rsaPublicKey.PublicExponent.ToBouncyCastleBigInteger()
                            );

                        //todo

                        PssSigner eng = new PssSigner(new RsaEngine(), digestAlgo, saltLength); //create new pss

                        eng.Init(false, publickey); //initiate this one

                        eng.BlockUpdate(dataForSignature, 0, dataForSignature.Length);

                        result = eng.VerifySignature(signatureToVerify);

                    }
                    return result;


                case KnownOids.ecPublicKey:
                    {
                        if (!(AlgorithmOidEnum == KnownOids.ecdsa_with_sha1 || AlgorithmOidEnum == KnownOids.ecdsa_with_sha256 || AlgorithmOidEnum == KnownOids.ecdsa_with_sha384 || AlgorithmOidEnum == KnownOids.ecdsa_with_sha512))
                        {
                            //incompatible public keys
                            return false;
                        }
                        // in case of ecdsa, the signature is a sequence of r and s that needs to be concatenated
                        ECDSA_Sig_Value ecdsaSignature = Utils.DerDecode<ECDSA_Sig_Value>(signatureToVerify);

                        byte[] subjectPublicKeyInfoData = Utils.DerEncodeAsByteArray<SubjectPublicKeyInfo>(subjectPublicKeyInfo);
                        Org.BouncyCastle.Asn1.Asn1Sequence asn1Sequence = (Org.BouncyCastle.Asn1.Asn1Sequence)Org.BouncyCastle.Asn1.Asn1Sequence.FromByteArray(subjectPublicKeyInfoData);
                        Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo x509SubjectPublicKeyInfo = Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo.GetInstance(asn1Sequence);

                        AsymmetricKeyParameter publicKeyParam = PublicKeyFactory.CreateKey(x509SubjectPublicKeyInfo);

                        // Create the ECDSA signer
                        ISigner signer = SignerUtilities.GetSigner(GetAlgorithmFromSignatureAlgorithm(AlgorithmOidEnum));
                        signer.Init(false, publicKeyParam);
                        signer.BlockUpdate(dataForSignature, 0, dataForSignature.Length);
                        result = signer.VerifySignature(signatureToVerify);
                    }
                    return result;
                default:
                    throw new NotImplementedException("Signature Algorithm : " + AlgorithmOidEnum + "(" + subjectPublicKeyInfo.Algorithm.Algorithm.Value + ") not yet implemented");
            }
        }

        private static string GetAlgorithmFromSignatureAlgorithm(KnownOids algorithmOidEnum)
        {
            switch (algorithmOidEnum)
            {
                case KnownOids.ecdsa_with_sha1: return "SHA-1withECDSA";
                case KnownOids.ecdsa_with_sha256: return "SHA-256withECDSA";
                case KnownOids.ecdsa_with_sha384: return "SHA-384withECDSA";
                case KnownOids.ecdsa_with_sha512: return "SHA-512withECDSA";
                //there is also sha 224 we dont use in epassportlibrary now
                //there is also NONE we dont use in epassportlibrary now
            }
            throw new NotImplementedException();
        }

        public static bool VerifySignatureV2(SubjectPublicKeyInfo subjectPublicKeyInfo, byte[] signatureSourceBytes, string signatureAlgorithmOid, byte[] signatureToVerify)
        {
            bool result = false;
            bool isSignatureVerifiedSuccessfully = VerifyDigestSignature(
                            subjectPublicKeyInfo,
                            null,
                            null,
                            signatureSourceBytes,
                            signatureToVerify,
                            signatureAlgorithmOid
                            );
            return isSignatureVerifiedSuccessfully;
        }
        public static bool VerifyDigestSignature(SubjectPublicKeyInfo subjectPublicKeyInfo, byte[] digestToVerify, string digestAlgorithmOid, byte[] signatureSourceBytes, byte[] signatureToVerify, string signatureAlgorithmOid)
        {
            bool result = false;
            KnownOids publicKeyAlgorithmOidEnum = Oids.ParseKnown(subjectPublicKeyInfo.Algorithm.Algorithm.Value);
            KnownOids signatureOidEnum = Oids.ParseKnown(signatureAlgorithmOid);
            if (digestToVerify == null && (publicKeyAlgorithmOidEnum == KnownOids.rsaEncryption || publicKeyAlgorithmOidEnum == KnownOids.rsassa_pss))
            {
                if (signatureOidEnum == KnownOids.ecdsa_with_sha1 || signatureOidEnum == KnownOids.ecdsa_with_sha256 || signatureOidEnum == KnownOids.ecdsa_with_sha384 || signatureOidEnum == KnownOids.ecdsa_with_sha512)
                {
                    //incompatible public keys
                    return false;
                }
            }
            if (digestToVerify == null && publicKeyAlgorithmOidEnum == KnownOids.ecPublicKey)
            {
                if (!(signatureOidEnum == KnownOids.ecdsa_with_sha1 || signatureOidEnum == KnownOids.ecdsa_with_sha256 || signatureOidEnum == KnownOids.ecdsa_with_sha384 || signatureOidEnum == KnownOids.ecdsa_with_sha512))
                {
                    //incompatible public keys
                    return false;
                }
            }
            if (signatureOidEnum == KnownOids.rsassa_pss)
            {
                publicKeyAlgorithmOidEnum = signatureOidEnum;
            }

            switch (publicKeyAlgorithmOidEnum)
            {
                case KnownOids.rsaEncryption:
                    {                        
                        RSAPublicKey rsaPublicKey = Utils.DerDecode<RSAPublicKey>(subjectPublicKeyInfo.SubjectPublicKey.Value);

                        byte[] modulus = rsaPublicKey.Modulus.ToMicrosoftBigEndianByteArray();
                        byte[] exponent = rsaPublicKey.PublicExponent.ToMicrosoftBigEndianByteArray();

                        //Create a new instance of RSACryptoServiceProvider.
                        using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(modulus.Length * 8))
                        {
                            //Create a new instance of RSAParameters.
                            RSAParameters RSAKeyInfo = new RSAParameters();

                            //Set RSAKeyInfo to the public key values.                             
                            RSAKeyInfo.Modulus = modulus;
                            RSAKeyInfo.Exponent = exponent;

                            //Import key parameters into RSA.
                            RSA.ImportParameters(RSAKeyInfo);

                            if (digestToVerify != null)
                            {
                                if (digestToVerify.Length == GetHashAlgoOutputSizeFromOid(digestAlgorithmOid))
                                {
                                    result = RSA.VerifyHash(digestToVerify, digestAlgorithmOid, signatureToVerify);
                                }
                            } else
                            {
                                result = RSA.VerifyData(signatureSourceBytes, signatureAlgorithmOid, signatureToVerify);
                            }
                        }
                    }
                    return result;


                case KnownOids.rsassa_pss:
                    {
                        RSAPublicKey rsaPublicKey = Utils.DerDecode<RSAPublicKey>(subjectPublicKeyInfo.SubjectPublicKey.Value);

                        int saltLength = 20;
                        IDigest digestAlgo = new Sha1Digest();                        

                        if (subjectPublicKeyInfo.Algorithm.isParametersPresent()) {
                            try
                            {
                                RSASSA_PSS_params rsassa_pss_params = Utils.DerDecode<RSASSA_PSS_params>(subjectPublicKeyInfo.Algorithm.Parameters);
                                digestAlgo = GetBouncyCastleHashAlgoInstanceFromOid(rsassa_pss_params.HashAlgorithm.Value.Algorithm.Value);
                                saltLength = (int)rsassa_pss_params.SaltLength;
                            } catch(Exception e)
                            {
                                if (digestAlgorithmOid == null)
                                {
                                    digestAlgo = GetBouncyCastleHashAlgoInstanceFromLength(signatureToVerify.Length);
                                } else
                                {
                                    digestAlgo = GetBouncyCastleHashAlgoInstanceFromOid(digestAlgorithmOid);
                                }
                                
                            }
                        }

                        RsaKeyParameters publickey = new RsaKeyParameters(
                            false, 
                            rsaPublicKey.Modulus.ToBouncyCastleBigInteger(),
                            rsaPublicKey.PublicExponent.ToBouncyCastleBigInteger()
                            );

                        ISigner eng;
                        if (digestAlgorithmOid == null)
                        {
                            eng = SignerUtilities.GetSigner("SHA384withRSAandMGF1");
                        }
                        else
                        {
                            eng = new PssSigner(new RsaEngine(), digestAlgo); //create new pss
                        }
                        // Create an RSA signer with the RSASSA-PSS algorithm
                        eng.Init(false, publickey); //initiate this one
                        eng.BlockUpdate(signatureSourceBytes, 0, signatureSourceBytes.Length);
                        try
                        {
                            result = eng.VerifySignature(signatureToVerify);
                        } catch(Exception e)
                        {
                            result = false;
                        }

                    }
                    return result;


                case KnownOids.ecPublicKey:
                    {
                        // in case of ecdsa, the signature is a sequence of r and s that needs to be concatenated
                        ECDSA_Sig_Value ecdsaSignature = Utils.DerDecode<ECDSA_Sig_Value>(signatureToVerify);

                        byte[] subjectPublicKeyInfoData = Utils.DerEncodeAsByteArray<SubjectPublicKeyInfo>(subjectPublicKeyInfo);
                        Org.BouncyCastle.Asn1.Asn1Sequence asn1Sequence = (Org.BouncyCastle.Asn1.Asn1Sequence)Org.BouncyCastle.Asn1.Asn1Sequence.FromByteArray(subjectPublicKeyInfoData);
                        Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo x509SubjectPublicKeyInfo = Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo.GetInstance(asn1Sequence);

                        AsymmetricKeyParameter publicKeyParam = PublicKeyFactory.CreateKey(x509SubjectPublicKeyInfo);

                        if (digestToVerify != null)
                        {
                            ECDsaSigner ecdsa = new ECDsaSigner();
                            ecdsa.Init(false, publicKeyParam);
                            result = ecdsa.VerifySignature(
                                digestToVerify,
                                ecdsaSignature.R.ToBouncyCastleBigInteger(),
                                ecdsaSignature.S.ToBouncyCastleBigInteger()
                            );
                        }
                        else
                        {
                            // Create the ECDSA signer
                            ISigner signer = SignerUtilities.GetSigner(GetAlgorithmFromSignatureAlgorithm(signatureOidEnum));
                            signer.Init(false, publicKeyParam);
                            signer.BlockUpdate(signatureSourceBytes, 0, signatureSourceBytes.Length);
                            result = signer.VerifySignature(signatureToVerify);
                        }
                    }
                    return result;

                default:
                    throw new NotImplementedException("Signature Algorithm : " + publicKeyAlgorithmOidEnum + "(" + subjectPublicKeyInfo.Algorithm.Algorithm.Value + ") not yet implemented");
            }
        }

        public static byte[] HashWithAlgorithm(string oid, byte[] input)
        {
            try
            {
                // Compute the hash of the input data
                byte[] hashedData = ComputeHash(oid, input);

                return hashedData;
            }
            catch (CryptographicException ex)
            {
                // Handle any exceptions that may occur during hashing
                Console.WriteLine("Error occurred during hashing: " + ex.Message);
                return null;
            }
        }

        public static bool CheckSignature(byte[] tbscertificate, byte[] publicKeyBytes)
        {
            try
            {
                X509CertificateParser certParser = new X509CertificateParser();
                X509Certificate cert = certParser.ReadCertificate(tbscertificate);

                // Load the public key
                AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(publicKeyBytes);
                // Verify the certificate
                cert.Verify(pubKey);
                return true;
            } catch (Exception ex)
            {
                return false;
            }
        }
        public static bool VerifySignedData(SignedData signedData)
        {
            Certificate certificate = null;
            return VerifySignedData(signedData, out certificate);
        }

        public static bool VerifySignedData(SignedData signedData, out Certificate certificate)
        {
            certificate = null;

            foreach (SignerInfo signerInfo in signedData.SignerInfos.Value)
            {
                byte[] digestToVerify = null;
                byte[] signatureSourceBytes = null;

                byte[] signature = signerInfo.Signature.Value;
                
                string digestAlgorithmOid = signerInfo.DigestAlgorithm.Value.Algorithm.Value;                

                string signatureAlgorithmOid = signerInfo.SignatureAlgorithm.Value.Algorithm.Value;

                KnownOids signatureOidEnum = Oids.ParseKnown(signatureAlgorithmOid);
                KnownOids digestOidEnum = Oids.ParseKnown(digestAlgorithmOid);

                //default values, if not signet atrs
                digestToVerify = ComputeHash(digestAlgorithmOid, signedData.EncapContentInfo.EContent);
                if (signatureOidEnum == KnownOids.rsassa_pss)
                {
                    signatureSourceBytes = digestToVerify;
                }

                BigInteger certificateSerialNumber = signerInfo.Sid.IssuerAndSerialNumber?.SerialNumber.Value ?? 0;

                // if SignedAttrs is Present then it should be used (SignedAttrs contains the eContent digest).
                if (signerInfo.isSignedAttrsPresent())
                {
                    foreach (ePassport.Attribute attribute in signerInfo.SignedAttrs.Value)
                    {
                        if (Oids.ParseKnown(attribute.Type.Value.Value) == KnownOids.messageDigest)
                        {
                            byte[] digest = ((List<byte[]>)attribute.Values)[0];
                            var test = Utils.Compare(digestToVerify, 0, digest, digest.Length - digestToVerify.Length, digestToVerify.Length);
                            // verify that econtent digest is matching
                            if (test == true)
                            {
                                // since it is matching, let's use the SignedAttrs as input for the digest
                                byte[] dataToHash = Utils.DerEncodeAsByteArray<SignedAttributes>(signerInfo.SignedAttrs);
                                if (signatureOidEnum == KnownOids.rsassa_pss)
                                {
                                    signatureSourceBytes = dataToHash;
                                }
                                digestToVerify = ComputeHash(digestAlgorithmOid, dataToHash);
                                break;
                            }
                        }

                    }
                }

                foreach (CertificateChoices certChoice in signedData.Certificates.Value)
                {
                    if (Utils.Compare(certChoice.Certificate.TbsCertificate.SerialNumber.Value.ToByteArray(), certificateSerialNumber.ToByteArray()) == true || certificateSerialNumber == 0)
                    {
                        bool isSignatureVerifiedSuccessfully = VerifyDigestSignature(
                            certChoice.Certificate.TbsCertificate.SubjectPublicKeyInfo,
                            digestToVerify,
                            digestAlgorithmOid,
                            signatureSourceBytes,
                            signature,
                            signatureAlgorithmOid
                            );
                        certificate = certChoice.Certificate;
                        return isSignatureVerifiedSuccessfully;
                    }
                }

            }

            return false;
        }



#region Extensions

        public static Org.BouncyCastle.Math.BigInteger ToBouncyCastleBigInteger(this BigInteger value)
        {
            List<byte> dataList = new List<byte>(value.ToByteArray());
            dataList.Reverse();
            return new Org.BouncyCastle.Math.BigInteger(dataList.ToArray());
        }

        public static byte[] ToMicrosoftBigEndianByteArray(this BigInteger value)
        {
            List<byte> dataList = new List<byte>(value.ToByteArray());
            dataList.Reverse();
            if (dataList[0] == 0x00)
            {
                dataList.RemoveAt(0);
            }            
            return dataList.ToArray();
        }

        public static IEnumerable<string> GeRevokedSerialNumbersFromCrl(byte[] crlData, List<ePassport.SubjectPublicKeyInfo> certs)
        {
            // Parse the CRL.
            X509CrlParser crlParser = new X509CrlParser();
            X509Crl crl = crlParser.ReadCrl(crlData);
            bool failed = true;
            int count = certs.Count;
            int now = 0;
            foreach (var certEntry in certs)
            {
                now++;
                try
                {
                    byte[] certEntryBytes = Utils.DerEncodeAsByteArray<SubjectPublicKeyInfo>(certEntry);
                    AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(certEntryBytes);
                    crl.Verify(pubKey);             
                    failed= false;
                    Console.WriteLine($"Key {now}/{count} valid according to CRL.");
                    break;
                } catch (Exception ex)
                {
                }
            }
            // Get the serial numbers of all revoked certificates.
            var revokedSerialNumbers = crl.GetRevokedCertificates()
                ?.Cast<X509CrlEntry>();
            if (revokedSerialNumbers == null) return new List<string>();
            if (failed)
            {
                Console.WriteLine("Verification failed, but revoked serials exists!");
            }
            var numbers = revokedSerialNumbers.Select(entry => entry.SerialNumber);
            return numbers.Select(x=>x.ToString());
        }

        #endregion
    }
}
