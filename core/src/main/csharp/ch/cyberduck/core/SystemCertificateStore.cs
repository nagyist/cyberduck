﻿// 
// Copyright (c) 2010-2022 Yves Langisch. All rights reserved.
// http://cyberduck.io/
// 
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// Bug fixes, suggestions and comments should be sent to:
// feedback@cyberduck.io
// 

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ch.cyberduck.core;
using ch.cyberduck.core.exception;
using ch.cyberduck.core.preferences;
using Ch.Cyberduck.Core.Interactivity;
using Ch.Cyberduck.Core.Ssl;
using java.io;
using java.security;
using java.security.cert;
using java.util;
using org.apache.logging.log4j;
using X509Certificate = java.security.cert.X509Certificate;

namespace Ch.Cyberduck.Core
{
    public class SystemCertificateStore : CertificateStore
    {
        private static readonly Logger Log = LogManager.getLogger(typeof(SystemCertificateStore).FullName);

        public X509Certificate choose(CertificateIdentityCallback prompt, string[] keyTypes, Principal[] issuers,
            Host bookmark)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection found = new X509Certificate2Collection();
                foreach (Principal issuer in issuers)
                {
                    // JBA 20141028, windows is expecting EMAILADDRESS in issuer name, but the rfc1779 emits it as an OID, which makes it not match
                    // this is not the best way to fix the issue, but I can't find anyway to get an X500Principal to not emit EMAILADDRESS as an OID
                    string rfc1779 = issuer.toString()
                        .Replace("EMAILADDRESS=", "E=")
                        .Replace("ST=", "S=")
                        .Replace("SP=", "S=");
                    Log.debug("Query certificate store for issuer name " + rfc1779);

                    X509Certificate2Collection certificates =
                        store.Certificates.Find(X509FindType.FindByIssuerDistinguishedName, rfc1779, true);
                    found.AddRange(certificates);
                    foreach (X509Certificate2 certificate in certificates)
                    {
                        Log.debug("Found certificate with DN " + certificate.IssuerName.Name);
                    }
                }

                if (found.Count > 0)
                {
                    X509Certificate2Collection selected = X509Certificate2UI.SelectFromCollection(found,
                        LocaleFactory.localizedString("Choose"), string.Format(LocaleFactory.localizedString(
                                "The server requires a certificate to validate your identity. Select the certificate to authenticate yourself to {0}."),
                            bookmark.getHostname()), X509SelectionFlag.SingleSelection);
                    foreach (X509Certificate2 c in selected)
                    {
                        return ConvertCertificate(c);
                    }
                }

                throw new ConnectionCanceledException();
            }
            finally
            {
                store.Close();
            }
        }

        public bool verify(CertificateTrustCallback prompt, String hostName, List certs)
        {
            X509Certificate2 serverCert = ConvertCertificate(certs.get(0) as X509Certificate);
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode =
                PreferencesFactory.get().getBoolean("connection.ssl.x509.revocation.online")
                    ? X509RevocationMode.Online
                    : X509RevocationMode.Offline;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 0, 10); // set timeout to 10 seconds
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            for (int index = 1; index < certs.size(); index++)
            {
                chain.ChainPolicy.ExtraStore.Add(ConvertCertificate(certs.get(index) as X509Certificate));
            }

            chain.Build(serverCert);
            if (CheckForException(hostName, serverCert))
            {
                // Exceptions always have precedence
                return true;
            }

            string errorFromChainStatus = GetErrorFromChainStatus(chain, hostName);
            bool hostnameMismatch = hostName != null &&
                                    !HostnameVerifier.CheckServerIdentity(certs.get(0) as X509Certificate,
                                        serverCert, hostName);

            // check if host name matches
            if (null == errorFromChainStatus && hostnameMismatch)
            {
                errorFromChainStatus =
                    string.Format(LocaleFactory.localizedString(
                        "The certificate for this server is invalid. You might be connecting to a server that is pretending to be {0} which could put your confidential information at risk. Would you like to connect to the server anyway?",
                        "Keychain"), hostName);
            }

            if (null != errorFromChainStatus)
            {
                // Force use of ThreadLocal, otherwise we can't persist X.certificate.accept
                using (DialogPromptCertificateTrustCallback.Register(() =>
                {
                    PreferencesFactory.get()
                        .setProperty(hostName + ".certificate.accept", GetSha2Thumbprint(serverCert));
                }))
                {
                    try
                    {
                        prompt.prompt(errorFromChainStatus, certs);
                    }
                    catch (ConnectionCanceledException)
                    {
                        return false;
                    }
                }
            }

            return true;
        }

        public static IReadOnlyCollection<string> ListAliases()
        {
            using X509Store store = new(StoreName.My, StoreLocation.CurrentUser);
            HashSet<string> certs = new();
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 certificate in store.Certificates)
            {
                var alias = string.IsNullOrWhiteSpace(certificate.FriendlyName)
                    ? certificate.GetNameInfo(X509NameType.SimpleName, false)
                    : certificate.FriendlyName;
                if (!certs.Add(alias) && Log.isDebugEnabled())
                {
                    Log.debug($"Skipping duplicate alias \"{alias}\"");
                }
            }

            return certs;
        }

        public static X509Certificate2 ConvertCertificate(X509Certificate certificate)
        {
            return new X509Certificate2(certificate.getEncoded());
        }

        public static X509Certificate ConvertCertificate(X509Certificate2 certificate)
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certificate.RawData));
        }

        private bool CheckForException(string hostname, X509Certificate2 cert)
        {
            string accCert = PreferencesFactory.get().getProperty(hostname + ".certificate.accept");
            if (Utils.IsNotBlank(accCert))
            {
                var sha2 = GetSha2Thumbprint(cert);
                if (accCert.Equals(sha2))
                {
                    return true;
                }
                if (accCert.Equals(cert.Thumbprint))
                {
                    // Replace legacy SHA-1 thumbprint with SHA-256
                    PreferencesFactory.get()
                        .setProperty(hostname + ".certificate.accept", sha2);
                    return true;
                }
            }

            return false;
        }

        private string GetErrorFromChainStatus(X509Chain chain, string hostName)
        {
            string error = null;
            foreach (X509ChainStatus status in chain.ChainStatus)
            {
                if ((status.Status & X509ChainStatusFlags.RevocationStatusUnknown) ==
                    X509ChainStatusFlags.RevocationStatusUnknown ||
                    ((status.Status & X509ChainStatusFlags.OfflineRevocation) ==
                     X509ChainStatusFlags.OfflineRevocation))
                {
                    //due to the offline revocation check
                    continue;
                }

                if ((status.Status & X509ChainStatusFlags.NotTimeValid) == X509ChainStatusFlags.NotTimeValid)
                {
                    //certificate is expired, CSSM_CERT_STATUS_EXPIRED
                    error =
                        string.Format(LocaleFactory.localizedString(
                            "The certificate for this server has expired. You might be connecting to a server that is pretending to be {0} which could put your confidential information at risk. Would you like to connect to the server anyway?",
                            "Keychain"), hostName);
                    break;
                }

                if (((status.Status & X509ChainStatusFlags.UntrustedRoot) == X509ChainStatusFlags.UntrustedRoot) ||
                    (status.Status & X509ChainStatusFlags.PartialChain) == X509ChainStatusFlags.PartialChain)
                {
                    // untrusted self-signed, !CSSM_CERT_STATUS_IS_IN_ANCHORS && CSSM_CERT_STATUS_IS_ROOT
                    error =
                        string.Format(LocaleFactory.localizedString(
                            "The certificate for this server was signed by an unknown certifying authority. You might be connecting to a server that is pretending to be {0} which could put your confidential information at risk. Would you like to connect to the server anyway?",
                            "Keychain"), hostName);
                    break;
                }

                //all other errors we map to !CSSM_CERT_STATUS_IS_IN_ANCHORS
                Log.debug("Certificate error" + status.StatusInformation);
                error =
                    string.Format(LocaleFactory.localizedString(
                        "The certificate for this server is invalid. You might be connecting to a server that is pretending to be {0} which could put your confidential information at risk. Would you like to connect to the server anyway?",
                        "Keychain"), hostName);
            }

            return error;
        }

        public static String GetSha2Thumbprint(X509Certificate2 cert)
        {
            byte[] hashBytes;
            using (var hasher = new SHA256Managed())
            {
                hashBytes = hasher.ComputeHash(cert.RawData);
            }

            StringBuilder builder = new(hashBytes.Length * 2);
            foreach (ref readonly var hashByte in hashBytes.AsSpan())
            {
                builder.Append(hashByte.ToString("x2"));
            }

            return builder.ToString();
        }
    }
}
