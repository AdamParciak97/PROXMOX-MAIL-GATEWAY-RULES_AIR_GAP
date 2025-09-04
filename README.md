# PROXMOX-MAIL-GATEWAY-RULES_AIR_GAP

## Assumptions and purpose

#### Purpose: maximally make it difficult to enter malicious attachments/files and suspicious content without sandboxing and without a URL/DNSBL reputation.
#### Environment: No internet; you have your own DNS (internal) and mail circulates in your domain/in-borted partners.


```diff
@@ #### The strategy : @@
+ #### Hard rules for file types and extensions (block/quarium).
+ #### More aggressive anti-spam thresholds (only local heuristics).
+ #### Subject/Headery to designate “from the outside” and make it easier for users.
+ #### Quarantine + reports so that nothing dangerous goes straight to the boxes.
+ #### SPF/DKIM/DMARC – in your DNS (inner) zone to enforce the sender’s authentication in a closed network.
```

## 1 STEP. MTA and DNS mode (without internet). Why: We reject as much “in front of the queue” as possible and make sure that PMG has quick access to internal DNS.

## Before-Queue Filtering (pre-SMTP)

#### Change options Before Queue Filtering on YES. Why: garbage and unauthorized files are discarded during SMTP sessions, minimizing backscatter and load.

<img width="565" height="663" alt="image" src="https://github.com/user-attachments/assets/171abff6-a4cf-4645-98b5-f747169f46de" />

## DNS (Enter the address(s) of your internal recursive DNS). Why: PMG and SpamAssassin need quick DNS responses (here – only your internal zones, without the internet).

<img width="550" height="424" alt="image" src="https://github.com/user-attachments/assets/1fc2ee0f-0025-4371-9076-1af9b3dcd724" />

## 2 STEP. Anti-spam probes (SpamAssassin – local heuristics). Why: Without URIBL/RBL, we have to rely more on local SA signals and our own rules.

#### Create rules on MAIL FILTER. Create Action Objects like this:
<img width="408" height="528" alt="image" src="https://github.com/user-attachments/assets/76707b49-14bb-442c-979b-9e173b337331" />

#### Create Spam Filter on Value 3,5,10.
<img width="959" height="398" alt="image" src="https://github.com/user-attachments/assets/efc387b3-cd75-4b6c-b82d-92b57496debe" />

#### FINAL RULES
<img width="1920" height="783" alt="image" src="https://github.com/user-attachments/assets/4ae021c9-c142-41f0-ab7b-4e15441ed50f" />

## 3 STEP. Hard filters ANNEXERS. Why: without sandbox, we block the cause of infection – executables, macros, scripts, “two-extension”, ISO/IMG images, etc.

#### Objects "What - Content Type" (more accurate than the tip itself). Create Content Type. 

<img width="1139" height="437" alt="image" src="https://github.com/user-attachments/assets/e707177c-7ca7-40a3-9d37-4801c0f0de57" />

#### Objects "What - Filename (Regex)". Why: the tip is also useful – catches variants smuggled in archives or rebranded. Offline – important: if you don’t have a sandbox, especially consider the archive lock (see below the rules). Encrypted ZIP/7z without a password, you won't scan anyway.
<img width="1604" height="309" alt="image" src="https://github.com/user-attachments/assets/4fc7a650-1e9f-4cb9-a669-caedba9bce9e" />

## 4 STEP. “Who objects” and “Trusted”. Why: allows you to drain from tone for trusted contractors (if you want at all).
<img width="898" height="292" alt="image" src="https://github.com/user-attachments/assets/cd7636ac-d94d-41a4-b453-8c4a4833ab49" />

## 5 STEP. Action objects – headings, modifications. Why: signaling to users and slot machines what happened to the email. Click Mail Filter --> Action Objects --> Add Header Attribute
#### For mail outside your domain:
<img width="390" height="245" alt="image" src="https://github.com/user-attachments/assets/87c76f4f-7271-4a06-a477-4c9d76f24847" />

#### Apply for rules and analyses:
<img width="403" height="243" alt="image" src="https://github.com/user-attachments/assets/e34276b5-2a6d-4a3d-ac04-0325ead973ac" />

## 6 STEP. Rules (Rules) – the heart of configuration. Enter: Configuration --> Mail Filter --> Rules --> Add. Below are the proposals of the set (orders matter; more “blocking” at the top).

#### 1 rule. Inbound – Block Dangerous Files. Why: this is the main dial instead of sandbox.
<img width="428" height="807" alt="image" src="https://github.com/user-attachments/assets/8171a7c3-c6d2-4124-9d76-323fa200a5f1" />

#### 2 rule. Inbound – Block Archives (no-sandbox policy) (optional, but recommend offline). Why: encrypted ZIP/7z is the most common carrier; no sandbox and no reputation is a real risk.
<img width="424" height="775" alt="image" src="https://github.com/user-attachments/assets/d22b8f99-76af-4550-9006-4f4ab2f80e3f" />

#### 3 rule. Inbound – Mark External. Why: “human firewall” – the users see that it’s not from the inside.
<img width="429" height="721" alt="image" src="https://github.com/user-attachments/assets/9a067ee5-0a21-47a1-82e6-a70ce0e5cd6a" />

#### 4 rule. Outbound – Policy. Why: reduces the risk of “disguiding” hazards/exfiltration as EXE/ISO/JAR, etc.
<img width="427" height="859" alt="image" src="https://github.com/user-attachments/assets/7228af90-9c32-47d1-b784-6ae2554be7f3" />

## 7 STEP. Quarantine and reports. Why: Offline, suspicious emails do not enter the boxes without control. nter: Configuration - Spam Detector - Quarantine. Quarantine Host: type FQDN of PMG server, e.g. pmg.test.pl
<img width="568" height="359" alt="image" src="https://github.com/user-attachments/assets/b7ab0486-ac16-472b-9d4f-2332c3dd86df" />

## 8 STEP. Simple rules SpamAssassin locally (offline). Why: URIBL/RBL will not work, but we can add simple local rules (e.g. multiple URLs in content, DOCM patterns). WE strengthen scoring where the sandbox would normally “cure”.

#### Open the file: /etc/spamassassin/local.cfand add (examples):

```bash
# +2 points if the message contains >=2 http/https links
uri LOCAL_MANY_HTTP /https?:\/\/[^\s<>()]{10,}/
score LOCAL_MANY_HTTP 2.0
describe LOCAL_MANY_HTTP Message contains one or more HTTP links

# +3 points for files with macros (if SA catches it in the MIME headers)
header LOCAL_OFFICE_MACRO Content-Type =~ /macroEnabled/i
score LOCAL_OFFICE_MACRO 3.0
describe LOCAL_OFFICE_MACRO Office document with macros

# +3 points for the typical "double extension" in attachment names
mimeheader LOCAL_DOUBLE_EXT Content-Disposition =~ /\.(?:[a-z0-9]{1,6})\.(exe|js|vbs|scr|bat|cmd|com)(?="|;)/i
score LOCAL_DOUBLE_EXT 3.0
describe LOCAL_DOUBLE_EXT Attachment has double extension

# +2.5 points if the message has an archive attachment (zip/rar/7z)
mimeheader LOCAL_ARCHIVE Content-Type =~ /application\/(zip|x-7z-compressed|x-rar)/i
score LOCAL_ARCHIVE 2.5
describe LOCAL_ARCHIVE Archive attachment present
```

#### Apply changes command

```bash
systemctl restart pmg-smtp-filter
```
## 9 STEP. TLS (inside). Why: consistent, encrypted traffic between PMG and your servers. Enter: Configuration - Mail Proxy - TLS Policy. Add policy to your internal domains/hosts: Require TLS, minimally TLS 1.2.
<img width="907" height="824" alt="image" src="https://github.com/user-attachments/assets/69140788-fe92-4cb7-b138-13d5a7e7978c" />
