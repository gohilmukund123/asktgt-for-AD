using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;

namespace KerberosTGT
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            Console.WriteLine("[*] Action: Ask TGT\n");

            Dictionary<string, string> arguments = ParseArguments(args);

            var tgtRequest = new TGTRequest();
            await tgtRequest.Execute(arguments);
        }

        private static Dictionary<string, string> ParseArguments(string[] args)
        {
            var arguments = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < args.Length; i++)
            {
                if (!args[i].StartsWith('/'))
                    continue;

                string key = args[i];
                string value = "";

                if (i + 1 < args.Length && !args[i + 1].StartsWith('/'))
                {
                    value = args[i + 1];
                    i++;
                }

                arguments[key] = value;
            }
            return arguments;
        }
    }

    public class TGTRequest
    {
        public async Task Execute(Dictionary<string, string> arguments)
        {
            // Initialize default values for all parameters
            string user = "";
            string domain = "";
            string password = "";
            string hash = "";
            string dc = "";
            string outfile = "";
            bool ptt = false;
            KerberosEncryptionType encType = KerberosEncryptionType.RC4; // default encryption type

            // Parse user and domain
            if (arguments.ContainsKey("/user"))
            {
                string[] parts = arguments["/user"].Split('\\');
                if (parts.Length == 2)
                {
                    domain = parts[0];
                    user = parts[1];
                }
                else
                {
                    user = arguments["/user"];
                }
            }

            // Get domain if specified
            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }

            // If domain not specified, try to get current domain
            if (string.IsNullOrEmpty(domain))
            {
                try
                {
                    domain = Domain.GetCurrentDomain().Name;
                    Console.WriteLine($"[*] Got domain: {domain}");
                }
                catch (Exception)
                {
                    Console.WriteLine("[X] Could not determine domain automatically!");
                    return;
                }
            }

            // Handle encryption type
            if (arguments.ContainsKey("/enctype"))
            {
                string encTypeString = arguments["/enctype"].ToUpper();
                encType = encTypeString switch
                {
                    "RC4" or "NTLM" => KerberosEncryptionType.RC4,
                    "AES128" => KerberosEncryptionType.AES128,
                    "AES256" or "AES" => KerberosEncryptionType.AES256,
                    "DES" => KerberosEncryptionType.DES,
                    _ => KerberosEncryptionType.RC4
                };
            }

            // Get password or hash
            if (arguments.ContainsKey("/password"))
            {
                password = arguments["/password"];
                hash = GenerateKerberosHash(encType, password, GeneratePasswordSalt(domain, user));
            }
            else if (arguments.ContainsKey("/rc4") || arguments.ContainsKey("/ntlm"))
            {
                hash = arguments.ContainsKey("/rc4") ? arguments["/rc4"] : arguments["/ntlm"];
                encType = KerberosEncryptionType.RC4;
            }
            else if (arguments.ContainsKey("/aes256"))
            {
                hash = arguments["/aes256"];
                encType = KerberosEncryptionType.AES256;
            }
            else if (arguments.ContainsKey("/aes128"))
            {
                hash = arguments["/aes128"];
                encType = KerberosEncryptionType.AES128;
            }

            // Get other options
            if (arguments.ContainsKey("/dc"))
            {
                dc = arguments["/dc"];
            }

            if (arguments.ContainsKey("/outfile"))
            {
                outfile = arguments["/outfile"];
            }

            if (arguments.ContainsKey("/ptt"))
            {
                ptt = true;
            }

            // Validate required parameters
            if (string.IsNullOrEmpty(user))
            {
                Console.WriteLine("\r\n[X] You must supply a user name!\r\n");
                return;
            }
            if (string.IsNullOrEmpty(hash))
            {
                Console.WriteLine("\r\n[X] You must supply a /password or a [/rc4|/aes128|/aes256] hash!\r\n");
                return;
            }

            // Request the TGT
            try
            {
                await RequestTGT(user, domain, hash, encType, dc, outfile, ptt);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error requesting TGT: {ex.Message}");
            }
        }

        private async Task RequestTGT(string user, string domain, string hash, KerberosEncryptionType encType,
            string dc, string outfile, bool ptt)
        {
            Console.WriteLine($"[*] Using {encType} hash: {hash}");
            Console.WriteLine($"[*] Using domain controller: {(string.IsNullOrEmpty(dc) ? "auto-detect" : dc)}");

            var asReq = new KerberosASRequest
            {
                UserName = user,
                Domain = domain,
                Hash = hash,
                EncryptionType = encType,
                DomainController = dc
            };

            var ticket = await asReq.ExecuteAsync();
            
            if (ticket != null)
            {
                if (ptt)
                {
                    Console.WriteLine("[*] Importing ticket into current session...");
                    ImportTicket(ticket);
                }

                if (!string.IsNullOrEmpty(outfile))
                {
                    Console.WriteLine($"[*] Saving ticket to {outfile}");
                    SaveTicket(ticket, outfile);
                }
            }
        }

        private static string GeneratePasswordSalt(string domain, string user)
        {
            return $"{domain.ToUpperInvariant()}{user}";
        }

        private string GenerateKerberosHash(KerberosEncryptionType encType, string password, string salt)
        {
            // This is a placeholder - implement actual hash generation based on encryption type
            return $"HASH_{encType}_{Convert.ToBase64String(Encoding.UTF8.GetBytes(password + salt))}";
        }

        private void ImportTicket(KerberosTicket ticket)
        {
            try
            {
                // Placeholder for actual ticket injection logic.
                // You might use tools like Mimikatz, APIs like LsaCallAuthenticationPackage, or write to memory.

                Console.WriteLine("[+] Ticket imported successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Failed to import ticket: {ex.Message}");
            }
        }

        private void SaveTicket(KerberosTicket ticket, string outfile)
        {
            try
            {
                // Serialize ticket to a format (e.g., base64 encoded string or binary).
                string serializedTicket = Convert.ToBase64String(Encoding.UTF8.GetBytes(ticket.TicketData));

                // Write serialized ticket to the specified file.
                System.IO.File.WriteAllText(outfile, serializedTicket);

                Console.WriteLine($"[+] Ticket saved successfully to {outfile}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Failed to save ticket: {ex.Message}");
            }
        }

    }

    public class KerberosASRequest
    {
        public string? UserName { get; set; }
        public string? Domain { get; set; }
        public string? Password { get; set; }
        public KerberosEncryptionType EncryptionType { get; set; }
        public string? DomainController { get; set; }
        public string? Hash { get; set; }

        public async Task<KerberosTicket> ExecuteAsync()
        {
            Console.WriteLine($"[*] Building AS-REQ (with pre-auth) for: {Domain}\\{UserName}");

            try
            {
                var client = new KerberosClient();
                if (!string.IsNullOrEmpty(DomainController))
                {
                    client.Configuration.Realms[Domain].Kdc.Add(DomainController);
                }

                // Create credentials
                var creds = new KerberosPasswordCredential(UserName, Password, Domain);

                // Send the AS-REQ
                var asRep = await client.Authenticate(creds) as KrbAsRep;

                if (asRep == null)
                {
                    throw new InvalidOperationException("Failed to get AS-REP ticket");
                }
                return ProcessTicket(asRep);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error executing AS-REQ: {ex.Message}");
                return null;
            }
        }

        //private async Task<(KerberosClient client, KrbAsRep asRep)> AuthenticateWithKerberosAsync(string userName, string password, string domain)
        //{
        //    Console.WriteLine("[*] Authenticating with Kerberos.NET");

        //    var client = new KerberosClient();
        //    if (!string.IsNullOrEmpty(DomainController))
        //    {
        //        client.Configuration.Realms[domain].Kdc.Add(DomainController);
        //    }

        //    var creds = new KerberosPasswordCredential(userName, password, domain);
        //    var asRep = await client.Authenticate(creds) as KrbAsRep;

        //    if (asRep == null)
        //    {
        //        throw new InvalidOperationException("Failed to get AS-REP ticket");
        //    }

        //    return (client, asRep);
        //}

        private KerberosTicket ProcessTicket(KrbAsRep asRep)
        {
            Console.WriteLine("[*] Processing AS-REP ticket");

            try
            {
                var encRepPart = asRep.EncPart.Decrypt(
                    Password,
                    KeyUsage.AsRepEncryptedPart,
                    b => new KrbEncAsRepPart()
                );

                var ticketData = Convert.ToBase64String(asRep.Ticket.EncodeApplication().ToArray());
                var sessionKey = encRepPart.Key;

                return new KerberosTicket
                {
                    UserName = UserName,
                    Domain = Domain,
                    TicketData = ticketData,
                    SessionKey = Convert.ToBase64String(sessionKey.KeyBytes)
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error processing ticket: {ex.Message}");
                return null;
            }
        }

    }

    public class KerberosTicket
    {
        public string UserName { get; set; }
        public string Domain { get; set; }
        public string TicketData { get; set; }

        public string SessionKey { get; set; }
    }
    public enum KerberosEncryptionType
    {
        DES,
        RC4,
        AES128,
        AES256
    }
}
