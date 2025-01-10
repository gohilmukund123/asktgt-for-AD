# asktgt-for-AD

![AD VISUALIZATION IRL](https://github.com/user-attachments/assets/e380a61f-7227-4958-994f-d333ecd16d6e)
AD VISUALIZATION


![TRUST ACROSS DOMAIN (tree root)](https://github.com/user-attachments/assets/f37fc76b-8749-4e5e-9f2d-0e1792b34152)
TRUST ACROSS DOMAIN (TREE ROOT)

Rubeus is a well-known post-exploitation tool designed for attacking and defending against Kerberos authentication in Windows environments. It is an open-source project and part of the PowerShell Empire ecosystem, but it is written in C#. It allows security professionals, penetration testers, and red teamers to manipulate Kerberos tickets and perform a variety of attacks against Active Directory environments.

Here's a comprehensive overview of **Rubeus**:

---

## **1. Purpose**
Rubeus is primarily used for attacking Kerberos in Active Directory environments. It provides capabilities for ticket-based authentication attacks, ticket manipulation, and Kerberos-related reconnaissance.

---

## **2. Key Features**
### **Ticket Manipulation**
- **Pass-the-Ticket (PtT):** Injects Kerberos tickets (TGTs or TGSs) into the current session for lateral movement.
- **Kerberoasting:** Extracts service tickets for offline cracking, targeting accounts with Service Principal Names (SPNs).
- **Overpass-the-Hash (Pass-the-Key):** Uses an NTLM hash to request a TGT, bypassing the need for plaintext credentials.
- **Golden Ticket:** Creates a forged TGT using a domain's KRBTGT account hash for persistent access.
- **Silver Ticket:** Creates forged service tickets (TGS) for specific services without interacting with the KDC.

### **Authentication Requests**
- **AS-REP Roasting:** Extracts AS-REP responses for accounts with "Do not require Kerberos preauthentication" enabled, allowing offline brute force.
- **S4U (Service-for-User):** Requests tickets on behalf of another user for privilege escalation.
- **DCSync:** Simulates a domain controller to retrieve secrets like KRBTGT hashes.

### **Operational Use**
- Extract and renew Kerberos tickets.
- Monitor and validate Kerberos tickets.
- Automate Kerberos ticket management.

---

## **3. Common Attack Scenarios**
### **Kerberoasting**
1. Identify SPNs associated with accounts.
2. Request Kerberos service tickets for these accounts.
3. Extract encrypted tickets and perform offline brute-force attacks to recover the associated account's plaintext password.

### **Golden Ticket Attack**
1. Obtain the KRBTGT hash from a domain controller.
2. Use Rubeus to generate a forged TGT for any user.
3. Use this ticket to gain domain admin privileges and maintain long-term persistence.

### **AS-REP Roasting**
1. Identify accounts with preauthentication disabled.
2. Request an AS-REP for these accounts.
3. Extract and crack the encrypted response offline.

### **Pass-the-Ticket**
1. Extract a valid TGT or TGS from a compromised user session.
2. Use Rubeus to inject the ticket into the current session to authenticate as the user.

---

## **4. Usage Examples**
### **Basic Syntax**
```plaintext
Rubeus.exe <command> [options]
```

### **Kerberoasting**
```plaintext
Rubeus kerberoast /format:hashcat
```

### **Pass-the-Ticket**
```plaintext
Rubeus ptt /ticket:<Base64EncodedTicket>
```

### **Extracting Tickets**
```plaintext
Rubeus dump /luid:<LogonSessionID>
```

### **Golden Ticket Generation**
```plaintext
Rubeus golden /rc4:<KRBTGT_NTLMHash> /user:<Username> /domain:<Domain> /sid:<DomainSID>
```

### **AS-REP Roasting**
```plaintext
Rubeus asreproast /user:<Username>
```

---

## **5. Installation**
Rubeus is typically compiled from its C# source code. The following steps outline the process:
1. Clone the Rubeus repository:
   ```bash
   git clone https://github.com/GhostPack/Rubeus.git
   ```
2. Open the project in Visual Studio.
3. Build the solution to generate the `Rubeus.exe` binary.

---

## **6. Defensive Measures**
Organizations can defend against Rubeus and similar tools by:
- **Enforcing Strong Password Policies:** Reduce the risk of offline brute force attacks by using complex passwords.
- **Monitoring Kerberos Traffic:** Identify unusual Kerberos activity, such as a large number of ticket requests.
- **Limiting Preauthentication Exemptions:** Ensure all user accounts require Kerberos preauthentication.
- **Protecting Service Accounts:** Use managed service accounts (MSAs) and rotate credentials regularly.
- **Detecting Anomalous Behavior:** Monitor for golden/silver ticket usage, especially long-duration tickets.

---

## **7. Key Commands**
Below are some commonly used commands in Rubeus:

| Command               | Description                                      |
|-----------------------|--------------------------------------------------|
| `kerberoast`          | Extracts service tickets for Kerberoasting.     |
| `asreproast`          | Extracts AS-REP responses for offline cracking. |
| `ptt`                 | Injects Kerberos tickets into the session.      |
| `dump`                | Dumps Kerberos tickets from memory.             |
| `tgtdeleg`            | Requests a TGT with delegation rights.          |
| `renew`               | Renews a Kerberos ticket.                       |
| `golden`              | Creates a forged golden ticket.                 |
| `silver`              | Creates a forged silver ticket.                 |

---

Here’s a **technical breakdown of the code** and its **usage**, covering the logic, flow, and functions step by step without generic explanations.

---

## **Code Purpose**
The code provides functionality to:
1. Request a Kerberos Ticket Granting Ticket (TGT) by authenticating with a KDC.
2. Support different credential types, including passwords and pre-computed hashes (RC4, AES).
3. Optionally inject the obtained ticket into the current session (`/ptt`) or save it to a file (`/outfile`).

---

## **Technical Flow**

### **Main Method**
1. **Action**: Reads arguments and initiates the TGT request.
   ```csharp
   Dictionary<string, string> arguments = ParseArguments(args);
   var tgtRequest = new TGTRequest();
   await tgtRequest.Execute(arguments);
   ```
   - Arguments are parsed into a dictionary (key-value pairs).
   - Delegates execution to the `TGTRequest.Execute()` method.

---

### **Argument Parsing** (`ParseArguments`)
- Converts command-line arguments like `/user Alice` to a dictionary.
- Handles cases where values are missing or improperly formatted.
  Example:
  ```plaintext
  Input: /user Alice /password Secret
  Output: {"/user": "Alice", "/password": "Secret"}
  ```

---

### **`TGTRequest.Execute` Method**
**Core Logic**:
1. Extracts required parameters:
   - `/user`: Username (`domain\user` or `user` format).
   - `/password`, `/rc4`, `/aes128`, `/aes256`: Credential types.
   - `/domain`: Kerberos realm or autodetected via `Domain.GetCurrentDomain()`.
   - `/enctype`: Encryption type (`RC4`, `AES128`, etc.).
   - `/dc`: Domain controller (KDC) to use.
   - `/outfile`: File to save the ticket.
   - `/ptt`: Injects the ticket into the current session if specified.

2. **Validates Input**:
   - Errors out if required parameters are missing (e.g., no user or hash/password).
   ```csharp
   if (string.IsNullOrEmpty(user)) { /* Print error */ }
   if (string.IsNullOrEmpty(hash)) { /* Print error */ }
   ```

3. **Processes Parameters**:
   - Generates a Kerberos hash if using a password (e.g., RC4 or AES keys).
   ```csharp
   hash = GenerateKerberosHash(encType, password, GeneratePasswordSalt(domain, user));
   ```

4. **Calls `RequestTGT`**:
   - Builds the Kerberos request and sends it to the KDC.

---

### **`RequestTGT` Method**
This is where the ticket is actually requested:
1. **Builds a `KerberosASRequest`**:
   - Contains user, domain, hash, encryption type, and DC details.
   ```csharp
   var asReq = new KerberosASRequest { /* Populate properties */ };
   ```

2. **Sends the Request**:
   - Calls `ExecuteAsync()` on the `KerberosASRequest` object.
   - The response is an AS-REP containing the TGT.

3. **Processes the Ticket**:
   - Injects the ticket into the current session (`/ptt` flag).
   ```csharp
   ImportTicket(ticket);
   ```
   - Saves the ticket to a file (`/outfile` flag).
   ```csharp
   SaveTicket(ticket, outfile);
   ```

---

### **`KerberosASRequest.ExecuteAsync` Method**
This is the low-level Kerberos interaction:
1. **Initializes `KerberosClient`**:
   - Configures the Kerberos client for the specified domain/KDC.
   ```csharp
   var client = new KerberosClient();
   if (!string.IsNullOrEmpty(DomainController)) {
       client.Configuration.Realms[Domain].Kdc.Add(DomainController);
   }
   ```

2. **Creates Credentials**:
   - If using a password:
     ```csharp
     var creds = new KerberosPasswordCredential(UserName, Password, Domain);
     ```
   - Sends an AS-REQ to the KDC for authentication:
     ```csharp
     var asRep = await client.Authenticate(creds) as KrbAsRep;
     ```

3. **Processes the AS-REP**:
   - Decrypts the encrypted part of the AS-REP using the provided password or hash.
   ```csharp
   var encRepPart = asRep.EncPart.Decrypt(Password, KeyUsage.AsRepEncryptedPart, b => new KrbEncAsRepPart());
   ```
   - Extracts the ticket and session key.

---

### **Ticket Post-Processing**
- **Import Ticket**:
  - Uses placeholder logic to inject the ticket into the current session.
  - Actual implementation depends on tools like `Mimikatz` or Windows APIs (`LsaCallAuthenticationPackage`).
  ```csharp
  ImportTicket(ticket);
  ```

- **Save Ticket**:
  - Encodes the ticket data (e.g., Base64) and saves it to the specified file.
  ```csharp
  string serializedTicket = Convert.ToBase64String(Encoding.UTF8.GetBytes(ticket.TicketData));
  File.WriteAllText(outfile, serializedTicket);
  ```

---

### **Hash Generation**
`GenerateKerberosHash()` generates a hash (placeholder logic):
- Combines the password and a salt (`domain + username`).
- Example (actual Kerberos hash generation logic should replace this):
```csharp
return $"HASH_{encType}_{Convert.ToBase64String(Encoding.UTF8.GetBytes(password + salt))}";
```

---

### **Usage Scenarios**

#### **Command-Line Arguments**
- **Basic TGT Request**:
  ```plaintext
  KerberosTGT.exe /user Alice /domain EXAMPLE.COM /password SecretPass
  ```
  - Requests a TGT for user `Alice` in the `EXAMPLE.COM` domain using `SecretPass`.

- **Hash-Based Authentication**:
  ```plaintext
  KerberosTGT.exe /user Alice /domain EXAMPLE.COM /aes256 [hash]
  ```
  - Uses the precomputed AES256 hash for authentication.

- **Specify a Domain Controller**:
  ```plaintext
  KerberosTGT.exe /user Alice /domain EXAMPLE.COM /password SecretPass /dc dc.example.com
  ```
  - Sends the request to the specified domain controller (`dc.example.com`).

- **Save the Ticket**:
  ```plaintext
  KerberosTGT.exe /user Alice /password SecretPass /outfile ticket.kirbi
  ```
  - Saves the ticket to the `ticket.kirbi` file.

- **Pass-the-Ticket**:
  ```plaintext
  KerberosTGT.exe /user Alice /password SecretPass /ptt
  ```
  - Injects the ticket into the current session.

#### **Supported Credential Types**
- `/password`: Cleartext password.
- `/rc4`, `/aes128`, `/aes256`: Precomputed Kerberos hashes.

#### **Supported Encryption Types**
- `RC4`, `AES128`, `AES256`, and `DES` (deprecated).

---

### **Why Use This?**
- Automates Kerberos authentication for legitimate or security assessment purposes.
- Facilitates tasks like ticket injection (e.g., Pass-the-Ticket) or saving TGTs for later use.

Let me know if you have more specific questions!
