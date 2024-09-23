# Enumeration
Enumeration Techniques

# Explore Google hacking and enumeration 

# AIM:

To use Google for gathering information and perform enumeration of targets

## STEPS:

### Step 1:

Install kali linux either in partition or virtual box or in live mode

### Step 2:

Investigate on the various Google hacking keywords and enumeration tools as follows:


### Step 3:
Open terminal and try execute some kali linux commands

## Pen Test Tools Categories:  

Following Categories of pen test tools are identified:
Information Gathering.

Google Hacking:

Google hacking, also known as Google dorking, is a technique that involves using advanced operators to perform targeted searches on Google. These operators can be used to search for specific types of information, such as sensitive data that may have been inadvertently exposed on the web. Here are some advanced operators that can be used for Google hacking:

site: This operator allows you to search for pages that are within a specific website or domain. For example, "site:example.com" would search for pages that are on the example.com domain.
Following searches for all the sites that is in the domain yahoo.com

filetype: This operator allows you to search for files of a specific type. For example, "filetype:pdf" would search for all PDF files.
Following searches for pdf file in the domain yahoo.com



intext: This operator allows you to search for pages that contain specific text within the body of the page. For example, "intext:password" would search for pages that contain the word "password" within the body of the page.


inurl: This operator allows you to search for pages that contain specific text within the URL. For example, "inurl:admin" would search for pages that contain the word "admin" within the URL.

intitle: This operator allows you to search for pages that contain specific text within the title tag. For example, "intitle:index of" would search for pages that contain "index of" within the title tag.

link: This operator allows you to search for pages that link to a specific URL. For example, "link:example.com" would search for pages that link to the example.com domain.

cache: This operator allows you to view the cached version of a page. For example, "cache:example.com" would show the cached version of the example.com website.

 
#DNS Enumeration


##DNS Recon
provides the ability to perform:
Check all NS records for zone transfers
Enumerate general DNS records for a given domain (MX, SOA, NS, A, AAAA, SPF , TXT)
Perform common SRV Record Enumeration
Top level domain expansion

## OUTPUT:

Google Hacking
1.

![WhatsApp Image 2024-09-23 at 18 36 08_f750180c](https://github.com/user-attachments/assets/21a0f0c4-1c04-4d98-bda4-514c15d6f8ee)

2.

![WhatsApp Image 2024-09-23 at 18 37 20_68369a69](https://github.com/user-attachments/assets/6416d0fe-1374-49cc-8ecf-0fb4b4225df0)

3.

![WhatsApp Image 2024-09-23 at 18 37 59_115e5fc6](https://github.com/user-attachments/assets/0ca272a6-282c-45f0-a5f6-687ee85c55c3)

4.

![WhatsApp Image 2024-09-23 at 18 38 53_f0cd6f41](https://github.com/user-attachments/assets/80d99113-0513-4ee4-ac85-312c194e6d14)

5.

![WhatsApp Image 2024-09-23 at 18 39 29_a97d57d0](https://github.com/user-attachments/assets/b997f22e-f17b-4e1a-8610-827f8ce3d6e8)

6. 

![WhatsApp Image 2024-09-23 at 18 40 01_6d4c79fa](https://github.com/user-attachments/assets/42a21f7b-7d45-4ca3-b2cf-2a2e0c668f37)
 






##dnsenum
Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain. The program currently performs the following operations:

Get the host’s addresses (A record).
Get the namservers (threaded).
Get the MX record (threaded).
Perform axfr queries on nameservers and get BIND versions(threaded).
Get extra names and subdomains via google scraping (google query = “allinurl: -www site:domain”).
Brute force subdomains from file, can also perform recursion on subdomain that have NS records (all threaded).
Calculate C class domain network ranges and perform whois queries on them (threaded).
Perform reverse lookups on netranges (C class or/and whois netranges) (threaded).
Write to domain_ips.txt file ip-blocks.
This program is useful for pentesters, ethical hackers and forensics experts. It also can be used for security tests.


##smtp-user-enum
Username guessing tool primarily for use against the default Solaris SMTP service. Can use either EXPN, VRFY or RCPT TO.


In metasploit list all the usernames using head /etc/passwd or cat /etc/passwd:

select any username in the first column of the above file and check the same


#Telnet for smtp enumeration
Telnet allows to connect to remote host based on the port no. For smtp port no is 25
telnet <host address> 25 to connect
and issue appropriate commands
  
 ##Output

 dnsrecon

 ![WhatsApp Image 2024-09-23 at 18 59 04_602db450](https://github.com/user-attachments/assets/39e40898-e615-488d-a6b4-cd12915f8426)

 ![WhatsApp Image 2024-09-23 at 18 59 46_f68163b7](https://github.com/user-attachments/assets/ba84c990-6e9e-497e-9c28-e1826571d1c0)

 dnsenum

 ![WhatsApp Image 2024-09-23 at 19 02 13_ee437b10](https://github.com/user-attachments/assets/7abe6c2f-080a-43ae-a433-238e3b4f5463)

 ![WhatsApp Image 2024-09-23 at 19 02 35_62ae06f1](https://github.com/user-attachments/assets/2a7d7e8f-de29-4bbc-bd28-d0cb47e24b51)




  

## nmap –script smtp-enum-users.nse <hostname>

The smtp-enum-users.nse script attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user accounts in the remote system.




## RESULT:
The Google hacking keywords and enumeration tools were identified and executed successfully

