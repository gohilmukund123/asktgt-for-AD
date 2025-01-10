# asktgt-for-AD

![AD VISUALIZATION IRL](https://github.com/user-attachments/assets/e380a61f-7227-4958-994f-d333ecd16d6e)

![TRUST ACROSS DOMAIN (tree root)](https://github.com/user-attachments/assets/f37fc76b-8749-4e5e-9f2d-0e1792b34152)

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

## **8. Practical Applications**
Rubeus is a favorite tool for red teams simulating real-world attacks and adversaries targeting Kerberos. However, it is also useful for blue teams in building detection and mitigation strategies.

---

## **9. Resources**
- [GitHub Repository](https://github.com/GhostPack/Rubeus)
- [Kerberos Overview (Microsoft Docs)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- Blogs and guides from red team and blue team experts detailing usage and countermeasures.
