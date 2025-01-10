# asktgt-for-AD

![AD VISUALIZATION IRL](https://github.com/user-attachments/assets/e380a61f-7227-4958-994f-d333ecd16d6e)
AD VISUALIZATION


![TRUST ACROSS DOMAIN (tree root)](https://github.com/user-attachments/assets/f37fc76b-8749-4e5e-9f2d-0e1792b34152)
TRUST ACROSS DOMAIN (TREE ROOT)

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
