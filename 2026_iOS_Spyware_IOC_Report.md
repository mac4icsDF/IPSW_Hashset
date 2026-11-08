# 2026 iOS Spyware & Malware Threat Intelligence Report

**Date:** 2026-11-07  
**Author:** OpenCode Research  
**Classification:** Open Source Threat Intelligence (OSINT)  
**Scope:** iOS / iPhone malware and spyware only (with selected historically significant iOS campaigns that are still referenced in 2026 reporting)  
**Sources:** Citizen Lab, Amnesty International Security Lab, Google Threat Intelligence Group, Kaspersky, Apple, MVT Project, iVerify, Lookout, Report URI, Censys, Sekoia, Confiant

---

## Executive Summary

This report focuses on iOS malware and spyware threats active or disclosed in 2026, plus a small number of historically significant iOS spyware families (Operation Triangulation, Graphite/Paragon) whose IOCs are still useful for threat hunting and attribution. Unlike desktop malware, iPhone spyware typically leverages **zero-click or one-click exploit chains**, **watering-hole attacks**, **malvertising**, **trojanized App Store apps**, or **ad-tech abuse**. Many families are mercenary, state-sponsored, or financially motivated, and are designed to leave minimal forensic traces.

The dominant iOS threats in 2026 are:
- **Pegasus** (NSO Group) — persistent zero-click mercenary spyware.
- **Predator** (Intellexa/Cytrox) — mercenary spyware with sophisticated pre-deployment checks and ad-based delivery (“Aladdin”).
- **Candiru / Integrity Labs** — mercenary spyware now delivered via targeted ads through the **AdFection** pipeline (Citizen Lab, October 2026).
- **Coruna / DarkSword** — leaked iOS exploit kits now used by multiple state-sponsored and financially motivated actors, including via malvertising, hijacked analytics tags, and open-directory exploitation-as-a-service platforms.
- **SparkCat / SparkKitty / FakeWallet** — App Store-distributed OCR-based or wallet-mimicking photo/seed stealers.
- **Packagist WebKit-to-kernel exploit chain** — drive-by spyware and crypto-wallet seed theft.
- **Graphite** (Paragon) — commercial zero-click iOS spyware with limited public IOCs.
- **Operation Triangulation** (2023) — historical iMessage zero-click APT campaign with reusable C&C list and forensic indicators.

**Important:** iOS spyware IOCs are intentionally scarce. Domains and IPs are often customer-specific and rotated quickly. Detection relies heavily on **forensic analysis** using tools like **MVT (Mobile Verification Toolkit)**, encrypted backups, sysdiagnose logs, and crash analysis — not just network blocking.

This report incorporates detailed IOCs and detection guidance from **Citizen Lab**, **iVerify**, **Lookout**, **Censys**, **Kaspersky**, **Sekoia**, **Google Threat Intelligence Group**, and **Amnesty International**.

---

## Table of Contents

1. [How iOS Spyware Differs from Android/Desktop](#1-how-ios-spyware-differs-from-androiddesktop)
2. [Pegasus for iOS](#2-pegasus-for-ios)
3. [Predator Spyware](#3-predator-spyware)
4. [Candiru / Integrity Labs & AdFection](#4-candiru--integrity-labs--adfection)
5. [Coruna iOS Exploit Kit](#5-coruna-ios-exploit-kit)
6. [DarkSword iOS Exploit Kit](#6-darksword-ios-exploit-kit)
7. [SparkCat / SparkKitty iOS Stealer](#7-sparkcat--sparkkitty-ios-stealer)
8. [FakeWallet iOS Crypto Stealer](#8-fakewallet-ios-crypto-stealer)
9. [Packagist iOS WebKit-to-Kernel Exploit Chain](#9-packagist-ios-webkit-to-kernel-exploit-chain)
10. [Graphite Spyware](#10-graphite-spyware)
11. [Operation Triangulation (2023, historical)](#11-operation-triangulation-2023-historical)
12. [Apple CVEs Relevant to iOS Spyware](#12-apple-cves-relevant-to-ios-spyware)
13. [Detection Methodology for iPhones](#13-detection-methodology-for-iphones)
14. [Defensive Recommendations for iOS](#14-defensive-recommendations-for-ios)
15. [Full IOC List](#15-full-ioc-list)
16. [Expanded IOCs from November 2026 Research Update](#16-expanded-iocs-from-november-2026-research-update)
17. [References](#17-references)

---

## 1. How iOS Spyware Differs from Android/Desktop

| Feature | iOS Spyware | Android/Desktop Malware |
|---|---|---|
| Installation method | Zero-click exploit, one-click exploit, trojanized App Store app, enterprise/sideloaded profile | Malicious APK/MSI, phishing download, exploit |
| User interaction | Often none (zero-click) | Usually requires click/install |
| Persistence | Kernel-level, memory-resident, sometimes modifies system partition | App/service persistence more visible |
| Detection difficulty | Very high — cleans logs, uses ephemeral C2, no app icon | Moderate — apps/processes often visible |
| IOC type | Process names, kernel extensions, C2 domains, exploit artifacts, filesystem artifacts, log messages | File hashes, EXE/APK names, IPs |
| Best detection tool | MVT on encrypted backup + sysdiagnose + crash logs + unified logs | EDR, antivirus, network logs |

---

## 2. Pegasus for iOS

**Attribution:** NSO Group  
**Type:** Mercenary zero-click spyware  
**Platform:** iOS  
**MITRE ATT&CK:** S0289  
**Disclosed 2026 activity:** Serbia student movement, University of Belgrade rector, EU/PEGA figures  
**Sources:** Citizen Lab, SHARE Foundation, Amnesty International Security Lab, iVerify, Lookout

### How It Works
1. **Initial Access (T1664):** Pegasus typically infects iPhones via **iMessage zero-click exploits**. The victim receives a specially crafted iMessage; no user interaction is required.
2. **Privilege Escalation (T1404):** Exploits iOS kernel or system vulnerabilities to gain root-level access.
3. **Persistence (T1645):** Modifies the system partition to survive reboots; uses process names that spoof legitimate iOS binaries.
4. **Data Collection:** Records audio, captures location, steals messages, emails, photos, passwords, encryption keys, and app data.
5. **C2 Communication:** Communicates with operator-controlled infrastructure over HTTPS/encrypted channels.
6. **Anti-Forensics:** Pegasus clears `shutdown.log` and other forensic artifacts. iOS 26 changed `shutdown.log` management, overwriting it on every reboot and erasing older evidence.

### 2026 Confirmed Activity
- **Serbia student movement member** — infected December 2025–January 2026 via iMessage zero-click (Citizen Lab/SHARE Foundation, September 2026).
- **Vladan Đokić**, Rector of University of Belgrade — Pegasus infection confirmed in 2026, six days before Serbia’s October 25 snap election.
- At least **16 people in Serbia** targeted with advanced spyware in 2026.
- Apple sent new threat notifications to users in **110+ countries** in 2026.
- iVerify’s May 2024 mobile threat hunt of 2,500 self-scanned devices found **7 Pegasus infections** across iOS 14–16, demonstrating wider prevalence than previously understood.

### Spoofed Process Names
Pegasus uses process names designed to look like legitimate iOS binaries. Examples from historical Amnesty/Lookout research:

| Pegasus Process | Spoofed iOS Binary |
|---|---|
| ABSCarryLog | ASPCarryLog |
| (other variants mimic `com.apple.assistd`, `com.apple.CoreTime`, etc.) |

### iVerify Forensic IOCs for Pegasus
For devices on **iOS < 26**, iVerify identified the following shutdown.log indicator:

| Type | Indicator | Description |
|------|-----------|-------------|
| File Path | `/private/var/db/com.apple.xpc.roleaccountd.staging/com.apple.WebKit.Networking` | Pegasus 2022 shutdown.log IOC |
| Log Correlation | `containermanagerd` logs vs `shutdown.log` boot events | For iOS 18 and earlier; discrepancies suggest log wiping |
| Artifact | Cleared/empty `shutdown.log` on a known-active device | Heuristic for suspicious device (Pegasus/Predator wipe behavior) |

### Lookout Historical Jailbreak Detection IOCs
From Lookout’s 2016 technical analysis of Pegasus (still relevant for historical samples and legacy detection):

| Type | Indicator | Description |
|------|-----------|-------------|
| File Path | `/--early-boot` | Early boot artifact |
| File Path | `/var/root/test.app` | Test app dropped during jailbreak |
| File Path | `/private/var/tmp/crw` | Jailbreak/write artifact |
| File Path | `/private/var/tmp/cr` | Jailbreak/write artifact |
| File Path | `/private/var/tmp/st_data` | Jailbreak staging data |

### Amnesty Inside Pegasus (July 2026) Key Insights
Amnesty’s analysis of NSO Group materials disclosed in the WhatsApp v. NSO litigation confirms:
- Pegasus uses per-customer “whitened” infrastructure (Apple IDs, domains, servers) registered by NSO’s **White Services** team.
- Unique attacker accounts and infection domains function as **customer fingerprints** — the same account/domain across multiple victims indicates the same customer.
- Pegasus supports **Covert** (zero-click) and **Triggered** (1-click) vectors, plus network injection and physical access.
- Historical iOS vectors include **Diablo** (iOS 11.x, VoWiFi), **Dragonfly** (iOS 12.x, iMessage), and the 2020–2021 iMessage/Photos zero-click chains.

### MITRE ATT&CK for Mobile
- T1664: Exploitation for Initial Access
- T1404: Exploitation for Privilege Escalation
- T1645: Compromise Client Software Binary
- T1429: Audio Capture
- T1430: Location Tracking
- T1636: Protected User Data
- T1644: Out of Band Data (SMS C2)
- T1421: System Network Connections Discovery

---

## 3. Predator Spyware

**Attribution:** Intellexa (formerly Cytrox)  
**Type:** Mercenary spyware  
**Platform:** iOS / Android  
**Sources:** Citizen Lab, Amnesty International, iVerify, Google Threat Intelligence Group

### How It Works
Predator is a commercial surveillance spyware sold to governments. It uses zero-click exploit chains for initial access, then deploys a sophisticated implant. iVerify notes that Predator runs an **eight-step validation process** before full deployment, checking:
- Whether the system log is being monitored.
- Whether the device is monitored for jailbreaks.
- Whether the user is running a proxy.
- Whether **Developer Mode** is enabled on the iPhone (if yes, Predator fails to install).

### Key iVerify / Amnesty / Google Findings
- Predator, like Pegasus, monitored and left traces in `shutdown.log`.
- iOS 26 overwrites `shutdown.log` on every reboot, erasing older Predator evidence.
- Enabling **iOS Developer Mode** can block Predator installation.
- Google GTIG analyzed a 2023 Intellexa iOS chain (internally **“smack”**) delivering Predator/**PREYHUNTER**. It uses WebKit RCE → kernel sandbox escape → privilege escalation.
- iVerify found Google-published Predator samples abused a legitimate App Store app (`com.elanbenami.EnneaApp`) and legitimate Team ID `5PN8QLT2JN` for CoreTrust signature bypass. A malicious second signature used Team ID `RUQSQXY3U9`.
- Amnesty’s December 2025 Intellexa leaks confirmed an ad-based zero-click vector called **Aladdin**, a network-injection vector, and Kazakhstan-targeting infrastructure codenamed **EAGLE_2**.

### MITRE ATT&CK for Mobile
- T1664: Exploitation for Initial Access
- T1645: Compromise Client Software Binary
- T1629: Impair Defenses (pre-deployment checks)
- T1636: Protected User Data

---

## 4. Candiru / Integrity Labs & AdFection

**Attribution:** Candiru (rebranded as Integrity Labs after acquisition by Integrity Partners, April/December 2025)  
**Type:** Mercenary spyware delivered via targeted ads  
**Platform:** iOS / Android / Windows  
**Disclosed:** October 2026  
**Sources:** Citizen Lab, Confiant

### How It Works
Citizen Lab’s **AdFection** report (October 2026) provides the first public technical confirmation of **zero-click mercenary spyware delivered via targeted online advertisements**. Devices at **Al Jazeera** were infected with Candiru spyware after being served ads purchased through **Discover-Tech**, an Israeli ad-tech firm that acts as a bridge between the advertising ecosystem and mercenary spyware vendors.

The attack flow:
1. Discover-Tech wins a real-time bidding auction and serves an ad to a website or app on the target device.
2. The ad contains a `<script>` tag contacting Discover-Tech’s **NOAS server**.
3. The NOAS server decides (based on advertising ID, cookie ID, IP address) whether to return JavaScript.
4. For selected targets, the server returns JavaScript that redirects to a **Candiru validator server**, then to a **Candiru C&C server**, ultimately installing spyware.
5. For non-targets, the server returns a 0-byte response, allowing mass profiling without obvious malicious payloads.

Discover-Tech’s **Controlium** platform allows spyware customers to target specific users by mobile advertising ID, browser cookie ID, or IP address, and to deliver “controlled ads” that can run arbitrary scripts or infection URLs.

### Key 2026 Discover-Tech / Controlium Infrastructure
| Type | Indicator | Description |
|------|-----------|-------------|
| Platform | `controlium[.]net` | Controlium admin/customer platform |
| Platform | `powerium[.]net` | Controlium instance |
| Platform | `adv45.volasim[.]com` | Controlium instance |
| Platform | `adv50.volasim[.]com` | Controlium instance |
| CNAME | `discovertech-alb-100966113.us-east-1.elb.amazonaws[.]com` | AWS ALB for Controlium |
| Auth0 | `discovertech.us.auth0.com` | Controlium Auth0 tenant |
| NOAS | `pqv2.mtrtb[.]com` | NOAS / Infinite FIFO v2 QA server |
| NOAS | `ppv2.mtrtb[.]com` | NOAS / Infinite FIFO v2 production server |
| NOAS | `noas.mtrtb[.]com` | Legacy NOAS |
| NOAS | `noas.powerium[.]net` | Legacy NOAS |
| NOAS | `qa-noas.powerium[.]net` | QA NOAS |
| Tracking | `events.platc-tester[.]com` | Mini Platform C NOAS |
| Tracking | `events-ui.myweb3id[.]io` | Mini Platform C UI |
| Tracking | `events-ui.discover-tech[.]io` | Mini Platform C UI |
| Tracking | `logger.powerium[.]net` | Event logger |
| Tracking | `logger.controlium[.]net` | Event logger |
| Tracking | `dtech.adtimizer[.]co` | Impression/click tracking (Beeswax) |
| Tracking | `imp.powerium[.]net` | Impression tracking |
| Tracking | `tracker.mtrtb[.]com` | Click/impression tracking |
| Tracking | `myipinfo[.]io` | Controlium OpSec decoder / MyIPInfo site |
| Tracking | `events.myweb3id[.]io` | ID syncing with Yandex |
| Tracking | `tracookiepixel[.]xyz` | ID syncing with Beeswax |
| Tracking | `js.tracookiepixel.xyz` | Tracking pixel JS |
| Tracking | `js.cookie-sync.xyz` | Older tracking pixel JS |
| Tracking | `cookiesurfer[.]com` | Tracking pixel site |
| Tracking | `mydsp[.]io` | Discover-Tech DSP |
| Tracking | `mtrtb[.]com` | Discover-Tech DSP / bidding data |
| Tracking | `discover-tech[.]io` | Corporate site / tracking pixel |
| Tracking | `relevantech[.]com` | Discover-Tech predecessor |
| Tracking | `akedo[.]gg` | Gaming platform / advertiser |
| Tracking | `citymaster[.]io` | Volasim game site |
| Tracking | `remindmewhere[.]app` | Volasim reminder app |
| Tracking | `volasim[.]com` | Digital marketing agency linked to Controlium |

### Candiru Validator & C&C Fingerprinting
Citizen Lab developed two fingerprints for Candiru servers:

**Fingerprint V1** (validator servers, 305 domains observed Aug 2022–Jul 2026):
```
HTTP/1\.1 [^\r\n]+\r\ndate: [^\r\n]+\r?\n(connection: [^\r\n]+\r\n)?content-type: [^\r\n]+\r\nserver: Apache[^\r\n]*\r\ncontent-length: [0-9]+\r\n.*
```
Example domains:
- `keyadapter[.]com`
- `sharethere[.]com`

**Fingerprint C1** (C&C servers):
```
HTTP/1\.1 [0-9]+ \r\nDate: [^\r\n]+\r?\nContent-Type: text/html[^\r\n]*\r\nContent-Length: [0-9]+\r\nConnection: keep-alive\r\nserver: nginx\r\n$
```
Example domains:
- `fearevolve[.]com`
- `insightenterprisells[.]com`
- `jobmarcher[.]com`
- `plasticbells[.]com`

### Candiru Sample and Infection Links
| Type | Indicator | Description |
|------|-----------|-------------|
| SHA256 | `255869de85e2a171993fc5eb8a556d873a1b8966e040f6f55926f2fa2d595cc8` | Candiru Windows DLL with C&C hardcoded (VirusTotal) |
| Domain | `sincereaccertain[.]com` | Candiru profiling server (2025) |
| CDN | `d1fcoizt7mje85.cloudfront[.]net` | Candiru/Discover-Tech Infinite FIFO CDN |
| Domain | `outdooutcome[.]com` | Candiru profiling domain (Mar 2025) |
| Domain | `suggestutterly[.]com` | Candiru profiling domain (Mar 2025) |

### MITRE ATT&CK for Mobile
- T1456: Drive-By Compromise
- T1658: Exploitation for Client Execution
- T1404: Exploitation for Privilege Escalation
- T1645: Compromise Client Software Binary
- T1636: Protected User Data
- T1041: Exfiltration Over C2 Channel

---

## 5. Coruna iOS Exploit Kit

**Disclosed:** March 2026  
**Aliases:** CryptoWaters  
**Type:** iOS exploit kit / drive-by compromise  
**Platform:** iOS  
**Targets:** iOS 13.0 through iOS 17.2.1  
**Attribution:** Originally surveillance-vendor customer; later leaked to cybercrime (UNC6691) and Russian espionage (UNC6353); iVerify linked to L3 Harris/Trenchant insider theft  
**Sources:** Google Threat Intelligence Group, iVerify, Lookout, Amnesty International, Censys

### How It Works
1. **Initial Access (T1456):** Victim visits a compromised or malicious website (watering hole). No app install or user click is needed beyond loading the page.
2. **Exploit Chain:** Coruna chains up to **23 individual exploits** across five complete exploit chains to escape Safari, escalate privileges, and install a persistent implant.
3. **Final Payload:** Deploys an implant that exfiltrates device data.
4. **C2 Communication:** Uses HTTPS with AES-encrypted POST data. The implant has hardcoded C2s and a **DGA fallback** using the seed string “lazarus” to generate 15-character `.xyz` domains; validates domains via Google public DNS.
5. **Proliferation:** Originally highly targeted, Coruna leaked and was adopted by financially motivated Chinese actors (fake crypto exchanges) and suspected Russian espionage groups.
6. **Anti-Detection:** Coruna backs out if **Lockdown Mode** is active or the user is browsing privately.

### Censys Open-Directory Cluster Findings (October 2026)
Censys discovered five open directories exposing the full DarkSword/Coruna exploitation-as-a-service platform. The Coruna payload module hash `1334417664270db20af705f422878c53c8378203` was byte-identical across multiple captures. A third delivery chain (`gooll/`) on the production server targets iOS 13.0–17.2.1 with a self-adaptive kernel stage that does not name its CVEs.

### MITRE ATT&CK for Mobile
- T1456: Drive-By Compromise
- T1658: Exploitation for Client Execution
- T1404: Exploitation for Privilege Escalation
- T1645: Compromise Client Software Binary
- T1071: Application Layer Protocol
- T1573: Encrypted Channel
- T1041: Exfiltration Over C2 Channel

### IOCs
| Type | Indicator | Description |
|------|-----------|-------------|
| SHA256 | `2a9d21ca07244932939c6c58699448f2147992c1f49cd3bc7d067bd92cb54f3a` | Coruna implant (`com.apple.assistd`) |
| Bundle ID | `com.apple.assistd` | Masquerading as Apple daemon |
| Bundle ID | `com.sixdays.trust` | Coruna module |
| SHA256 | `1fb9dedf1de81d387eff4bd5e747f730dd03c440157a66f20fdb5e95f64318c0` | Coruna module (`com.sixdays.trust`) |
| Bundle ID | `com.uniswap.mobile` | Coruna module |
| SHA256 | `4dc255504a6c3ea8714ccdc95cc04138dc6c92130887274c8582b4a96ebab4a8` | Coruna module (`com.uniswap.mobile`) |
| URL | `http://cdn[.]uacounter[.]com/stat[.]html` | UNC6353 Coruna delivery |
| URL | `https://ai-scorepredict[.]com/static/analytics[.]html` | UNC6691 Coruna delivery |
| URL | `https://m[.]pc6[.]com/test/tuiliu/group[.]html` | UNC6691 Coruna delivery |
| URL | `http://ddus17[.]com/tuiliu/group[.]html` | UNC6691 Coruna delivery |
| DGA seed | `lazarus` | Generates 15-char `.xyz` fallback C2 domains |
| Crypto | AES (key = SHA256 of static string) | C2 traffic encryption |

---

## 6. DarkSword iOS Exploit Kit

**Disclosed:** March 2026  
**Type:** iOS exploit kit / drive-by compromise  
**Platform:** iOS  
**Targets:** iOS 18.4 through iOS 18.7 (P7 variant); earlier chains also iOS 16.7; gooll chain iOS 13.0–17.2.1  
**Attribution:** Multiple actors: UNC6353 (Russia), UNC6748 (Middle East), PARS Defense (Iran), APT29-linked actors, financially motivated Chinese-speaking crypto-theft operators, Chinese-speaking exploitation-as-a-service operator (Censys)  
**Sources:** Google Threat Intelligence Group, iVerify, Lookout, Report URI, Sekoia, Zimperium zLabs, Censys

### How It Works
1. **Initial Access (T1456):** Victim visits a compromised website, malicious ad, or hijacked analytics tag. For DarkSword P7, a **half-click** (interacting with an ad) can trigger the chain.
2. **Exploit Chain:** DarkSword uses multiple Safari/WebKit and kernel vulnerabilities to achieve full device compromise. As of November 2026, at least **608 domains** were delivering Coruna-family code, including DarkSword.
3. **Final Payloads:**
   - **GHOSTBLADE** — full device data harvesting implant (UNC6353).
   - **GHOSTKNIFE** — cookie and session theft implant (UNC6748).
   - **P7 DarkSword** — iVerify-discovered variant with two-way C2, on-device keychain extraction, and crypto-wallet theft.
   - **plasma_core** — Censys-tracked implant with SpringBoard coordinator and 18+ wallet injection modules.
4. **C2 Communication:** Operates via actor-controlled domains and IPs, sometimes using raw IPs to evade DNS filtering.
5. **Adoption:** State-sponsored groups (APT29-linked) and commercial surveillance vendors have reused DarkSword, lowering the technical threshold for advanced mobile exploitation.

### Vulnerabilities Used
| CVE | Use | Patched In |
|---|---|---|
| CVE-2025-31277 | JIT RegExp match RCE (iOS 18.4–18.5) | iOS 18.6 |
| CVE-2025-43529 | WebContent JIT use-after-free / type confusion | iOS 26.2 / 18.7.3 |
| CVE-2026-20700 | TPRO/PAC bypass | iOS 26.3 |
| CVE-2025-14174 | ANGLE/GPU sandbox escape | iOS 26.2 / 18.7.3 |
| CVE-2025-43510 | AppleM2ScalerCSCDriver Copy-On-Write | iOS 26.1 / 18.7.2 |
| CVE-2025-43520 | Kernel privilege escalation | iOS 26.1 / 18.7.2 |
| CVE-2024-27834 | JavaScript malware/cookie theft (Class A path) | iOS 26.x |
| CVE-2024-4671 | Related campaign exploit | iOS 26.x |
| CVE-2025-24201 | WebKit sandbox escape alternative (< iOS 18.3.2) | iOS 18.3.2 |
| CVE-2025-31200 | CoreAudio zero-click claim (unverified) | unverified |
| CVE-2026-31001 | JavaScriptCore type confusion (iOS 26, development only) | iOS 26.x |

### Implant Behavior (iVerify Analysis)
DarkSword injects JavaScript implants into system processes via the kernel. Key target processes:
- **SpringBoard** — main agent loader.
- **configd** — keychain copier.
- **wifid** / **securityd** — WiFi password dump.
- **UserEventAgent** — iCloud dumper.

Targeted data includes keychain passwords, crypto wallet apps, SMS/iMessage, WhatsApp, Telegram, call history, contacts, location, Safari data, Notes, Photos, WiFi passwords, Health data, Mail, and installed apps.

### P7 DarkSword Variant (iVerify, October 2026)
P7 DarkSword is a more stealthy variant with two-way C2.

**C2 Endpoints:** `/beacon`, `/result`, `/a`, `/event`, `/u`, `/nb`, `/p`, `/war`  
**Hardcoded User-Agent:** iOS 18.5 Safari string  
**Hardcoded Content-Type for `/p`:** `multipart/form-data; boundary=------HqBound`

### Censys DarkSword/Coruna Open-Directory Findings (October 2026)
Censys found five open directories exposing the full platform. Key findings:
- **Open-directory cluster hosts:**
  - `43.134.165[.]205:9999` — Tencent Cloud, DS-Fusion v1.0 bundle
  - `166.88.95[.]90:9999` — Evoxt Japan, operational C2 with live telemetry
  - `23.148.212[.]237:8888` — operator analysis workspace, iOS 26 exploit development
  - `47.102.192[.]23:9876` — Alibaba Cloud, Coruna staging host
  - `156.239.230[.]120:8080/80` — full C2 platform with admin panel
- **Production capture infrastructure:**
  - `112.213.108[.]85` (`hdios[.]cn`) — live production server
  - `154.18.187[.]160` (`fc.rsqqq[.]top`) — backup delivery stack
  - `202.146.222[.]253` (`i.131422[.]com`) — old production
  - `203.91.77[.]253` (`st.onlinefc[.]top`) — operator work machine
- **Wild-build C2 (separate Chinese operator):**
  - `66ds[.]lol` (Cloudflare-fronted)
  - Origin: `101.35.158[.]183` (Tencent, Shanghai)
  - Self-signed CA: `Codex iOS Isolated Lab Root CA 2026`, O=`IPLCZ Test Lab`
  - Parent domains: `iplcz[.]cn`, `northlab[.]cn`, `g.northlab[.]cn`, `manager.g.northlab[.]cn`
- **C2 panel fleet:**
  - `154.217.250[.]206` — “C2 PANEL v3.0”, group `幽灵集团` (Ghost/Phantom Group)
  - `14.128.47[.]81` — same group name, different build
  - Forward DNS hostnames: `ccwu[.]cc`, `wumian[.]cc.cd`
- **Persistence on device:**
  - LaunchDaemon: `/Library/LaunchDaemons/com.apple.ds.agent.plist`
  - IPC channels: `/tmp/nb_cmd`, `/tmp/nb_result`
  - Cookies: `ds_uuid`, `ds_done`, `coruna-lab-session`

### DarkSword Detection (iVerify / Censys)
Because DarkSword does not launch its own process but injects into system processes, detection relies on:
- **Browser/Safari history** showing malicious initial domains.
- **Filesystem artifacts** (only detectable on-device or via full filesystem dump, not from backups).
- **Unified log messages** in `mediaplaybackd` containing `[DarkSword-WIFI-DUMP]`, `[CHAIN]`, `[MAIN]`, `[MIG_FILTER_BYPASS]`, `[TASKROP]`, etc.
- **Crash clusters** across `com.apple.WebKit.WebContent`, `com.apple.WebKit.GPU`, `mediaplaybackd`, `SpringBoard`, `wifid`, `configd`, `securityd`, `UserEventAgent` within a short window.
- **Kernel panics** caused by watchdog timers or `launchd` unexpectedly exiting.
- **YARA rules:** Censys published 44 YARA rules covering the full DarkSword/Coruna binary surface.

### MITRE ATT&CK for Mobile
- T1456: Drive-By Compromise
- T1658: Exploitation for Client Execution
- T1404: Exploitation for Privilege Escalation
- T1645: Compromise Client Software Binary
- T1539: Steal Web Session Cookie
- T1555: Credentials from Password Stores
- T1636: Protected User Data
- T1041: Exfiltration Over C2 Channel

---

## 7. SparkCat / SparkKitty iOS Stealer

**Disclosed:** June 2025; active 2026  
**Type:** Trojan stealer / spyware  
**Platform:** iOS and Android  
**Distribution:** Official Apple App Store, Google Play, third-party stores, sideloading via enterprise provisioning profiles  
**Attribution:** Unknown (likely financially motivated, Asia-focused)  
**Sources:** Kaspersky

### How It Works
1. **Distribution:** Hidden inside seemingly legitimate apps. On iOS, found inside the **`币coin`** cryptocurrency-tracking app on the **official App Store**. Also distributed via fake TikTok clones and gambling apps with developer provisioning profiles.
2. **Permission Abuse:** Requests access to the device’s **Photo library**.
3. **OCR-Based or Bulk Theft:**
   - **SparkCat** uses Apple’s **Vision framework** to perform OCR on screenshots in Photos, hunting for cryptocurrency wallet recovery phrases.
   - **SparkKitty** is less selective and exfiltrates all accessible photos; some variants use OCR.
4. **Exfiltration:** Uploads extracted data plus device identifiers to attacker-controlled servers via `/api/putImages`, `/api/putDataInfo`, etc.
5. **Persistence:** Registers a callback to monitor gallery changes and exfiltrate new photos in real time.

### iOS Technical Details (SparkKitty)
- Malicious payload delivered as fake `AFNetworking.framework` or `Alamofire.framework`, or as obfuscated libraries disguised as `libswiftDarwin.dylib`/`wc.dylib`.
- Entry point: `+[AFImageDownloader load]` selector (not present in original AFNetworking).
- Configuration retrieved from `Info.plist` keys `ccool` (`77e1a4d360e17fdbc`) and `ccc`, or from `UserDefaults` key `com.tt.cf`.
- AES-256-ECB decryption keys: `p0^tWut=pswHL-x>>:m?^.^)W` and `J9^tMnt=ptfHL-x>>:m!^.^)A`.
- C2 endpoints: `/api/getImageStatus`, `/api/putImages`, `/api/anheartbeat`, `/api/putDataInfo`, `/api/getStatus`.
- Enterprise provisioning profile Team ID: `EHQ3N2D5WH` (SINOPEC SABIC Tianjin Petrochemical Co. Ltd.)
- Bundle IDs: `com.ss-tpc.rd.rdcUniApp`, `com.zhiliaoapp.musically` (TikTok mod)
- Distribution pages: `accgngrid[.]com`, `byteepic[.]vip`

### MITRE ATT&CK for Mobile
- T1660: Phishing via Social Media / Third-Party App Stores
- T1414: Capture Audio / Video (via Vision OCR)
- T1636: Protected User Data (Photos)
- T1005: Data from Local System
- T1041: Exfiltration Over C2 Channel
- T1629: Impair Defenses (hidden in legitimate-looking frameworks)

---

## 8. FakeWallet iOS Crypto Stealer

**Disclosed:** April 2026  
**Type:** Trojan crypto-wallet seed stealer  
**Platform:** iOS (via App Store phishing + enterprise profiles)  
**Attribution:** Unknown financially motivated actors  
**Sources:** Kaspersky

### How It Works
Kaspersky found **26 phishing apps in the Apple App Store** that masqueraded as popular crypto wallets (MetaMask, Ledger, Trust Wallet, Coinbase, TokenPocket, imToken, Bitpie). After installation, the apps open a malicious browser link that mimics the App Store and uses abused iOS enterprise/provisioning profiles to install a trojanized wallet IPA. The malicious wallet injects a dylib (or modifies the app source) to steal the user’s recovery seed phrase, encrypts it with RSA, and exfiltrates it to attacker C2 servers.

### IOCs
| Type | Indicator | Description |
|------|-----------|-------------|
| Detection | `HEUR:Trojan-PSW.IphoneOS.FakeWallet.*` | Kaspersky detection |
| Detection | `HEUR:Trojan.IphoneOS.FakeWallet.*` | Kaspersky detection |
| Mimicked apps | MetaMask, Ledger, Trust Wallet, Coinbase, TokenPocket, imToken, Bitpie | Apps impersonated |
| URL | `https://www.gxzhrc.cn/download/` | Phishing download |
| URL | `https://appstoreios.com/DjZH?key=...` | Phishing download |
| URL | `https://crypto-stroe.cc/` | Phishing store |
| URL | `https://yjzhengruol.com/s/3f605f` | Phishing link |
| URL | `https://xz.apps-store.im/s/iuXt?key=...` | Sideload distribution |
| C2 | `https://kkkhhhnnn.com/api/open/postByTokenpocket` | Seed exfiltration |
| C2 | `https://helllo2025.com/api/open/postByTokenpocket` | Seed exfiltration |
| C2 | `https://sxsfcc.com/api/open/postByTokenpocket` | Seed exfiltration |
| C2 | `https://iosfc.com/ledger/ios/Rsakeycatch.php` | Ledger seed exfiltration |
| C2 | `https://nmu8n.com/tpocket/ios/Rsakeyword.php` | TokenPocket seed exfiltration |
| C2 | `https://zmx6f.com/btp/ios/receiRsakeyword.php` | Bitpie seed exfiltration |
| C2 | `https://api.dc1637.xyz` | C2 API |
| IP | `139.180.139.209` | Configuration host |

*(See IOC list for full MD5 hashes of infected IPAs and malicious dylibs.)*

### MITRE ATT&CK for Mobile
- T1660: Phishing
- T1636: Protected User Data
- T1555: Credentials from Password Stores
- T1041: Exfiltration Over C2 Channel

---

## 9. Packagist iOS WebKit-to-Kernel Exploit Chain

**Disclosed:** March 2026; updated August 2026  
**Type:** Drive-by WebKit-to-kernel spyware / crypto stealer  
**Platform:** iOS  
**Targets:** iOS 18.4 through iOS 18.6.x (iPhone XS through iPhone 16)  
**Attribution:** Unknown financially motivated actors  
**Sources:** Socket Security, The Hacker News

### How It Works
1. **Initial Access:** Website operators install trojanized **Composer / Packagist themes** (e.g., for OphimCMS / KKPhim). The injected JavaScript runs on site visitors.
2. **Device Profiling:** The script inserts a hidden iframe, determines iOS version, and loads an OS-specific exploit chain.
3. **Exploit Chain:** WebKit-to-kernel exploit chain ending in spyware installation. Apple patched the issue in **iOS 26.1**.
4. **Payload:** Adds an **iOS Keychain cryptocurrency wallet seed and mnemonic stealer**.
5. **Data Stolen:** Keychain data, Wi-Fi passwords, SMS, Photos, contacts, cookies, location history, account databases, and wallet seeds from Bitget, BitKeep, Bitpie, Phantom, Tonkeeper, Trust Wallet, and others.
6. **Redeployment:** Actors redeployed the chain around **August 12, 2026** with a new payload.

### MITRE ATT&CK for Mobile
- T1456: Drive-By Compromise
- T1658: Exploitation for Client Execution
- T1404: Exploitation for Privilege Escalation
- T1645: Compromise Client Software Binary
- T1555: Credentials from Password Stores (Keychain)
- T1636: Protected User Data
- T1041: Exfiltration Over C2 Channel

---

## 10. Graphite Spyware

**Active:** 2025  
**Type:** Commercial zero-click spyware  
**Platform:** iOS  
**Attribution:** Paragon Solutions (Graphite)  
**Sources:** Citizen Lab, Amnesty International

### How It Works
Graphite is a newer commercial spyware family observed in 2025. Citizen Lab provided the first forensic confirmation of Paragon’s iOS mercenary spyware targeting European journalists. It uses a **zero-click iMessage attack** and was mitigated as of **iOS 18.3.1**.

### IOCs
| Type | Indicator | Description |
|------|-----------|-------------|
| C2 URL | `https://46.183.184[.]91/` | Graphite C2 server |
| CVE | CVE-2025-43200 | Graphite/Paragon zero-click iMessage exploit, patched in iOS 18.3.1 |
| TTP | Zero-click iMessage | No user interaction |
| Note | Limited public IOCs | Fingerprint P1 and attacker iMessage account not published |

### MITRE ATT&CK for Mobile
- T1664: Exploitation for Initial Access
- T1645: Compromise Client Software Binary
- T1636: Protected User Data

---

## 11. Operation Triangulation (2023, historical)

**Disclosed:** June 2023  
**Type:** iMessage zero-click APT spyware  
**Platform:** iOS  
**Targets:** iOS up to 15.7 (per Kaspersky; no later deployments observed after publication)  
**Attribution:** Unknown  
**Sources:** Kaspersky

### Why Include This 2023 Campaign?
Operation Triangulation is the most thoroughly documented public iMessage zero-click forensic case. Its C&C list, network sequence, and backup-based indicators remain a valuable reference for iOS threat hunting, and its methodology is similar to later Pegasus/Graphite zero-click attacks.

### How It Works
1. Target receives an iMessage with a malicious attachment.
2. No user interaction required; the attachment triggers code execution.
3. Exploit downloads additional stages from C&C servers for privilege escalation.
4. Final payload is a fully-featured APT platform running with root privileges.
5. The initial message and exploit attachment are deleted.
6. The malware blocks iOS updates; victims see “Software Update Failed.”

### Forensic Indicators
- **BackupAgent** process appears in data usage (a deprecated binary).
- **IMTransferAgent** downloads the iMessage attachment (~242 KB).
- Modified directories in `Library/SMS/Attachments/<hex>/<hex>` with no actual attachment files.
- Modified preference files:
  - `com.apple.ImageIO.plist`
  - `com.apple.locationd.StatusBarIconManager.plist`
  - `com.apple.imservice.ids.FaceTime.plist`
- Data usage by `com.apple.WebKit.WebContent`, `powerd`, `lockdownd`.
- `com.apple.softwareupdateservicesd.plist` modified → update failures.

### C&C Domains
| Domain | Domain |
|---|---|
| addatamarket[.]net | backuprabbit[.]com |
| businessvideonews[.]com | cloudsponcer[.]com |
| datamarketplace[.]net | mobilegamerstats[.]com |
| snoweeanalytics[.]com | tagclick-cdn[.]com |
| topographyupdates[.]com | unlimitedteacup[.]com |
| virtuallaughing[.]com | web-trackers[.]com |
| growthtransport[.]com | anstv[.]net |
| ans7tv[.]net |

### MITRE ATT&CK for Mobile
- T1664: Exploitation for Initial Access
- T1404: Exploitation for Privilege Escalation
- T1636: Protected User Data
- T1041: Exfiltration Over C2 Channel
- T1562.001: Impair Command History Logging / Impair Defenses

---

## 12. Apple CVEs Relevant to iOS Spyware

| CVE | Affected Product | Fixed In | Relevance |
|---|---|---|---|
| CVE-2025-43200 | iOS iMessage | iOS 18.3.1 | Graphite/Paragon zero-click |
| CVE-2023-41993 | WebKit/Safari | iOS 16.7 / 17.0 | Predator WebKit RCE (GTIG “smack” chain) |
| CVE-2023-41992 | Kernel IPC | iOS 16.7 / 17.0 | Predator sandbox escape / LPE |
| CVE-2023-41991 | iOS code signing | iOS 16.7 / 17.0 | Predator LPE |
| CVE-2025-48543 | Intellexa/Predator chain | Various | Intellexa exploit |
| CVE-2025-6554 | Intellexa/Predator chain | Various | Intellexa exploit |
| CVE-2024-4610 | Intellexa/Predator chain | Various | Intellexa exploit |
| CVE-2025-31277 | WebKit JIT RegExp match | iOS 18.6 | DarkSword iOS 18.4–18.5 RCE |
| CVE-2025-43529 | WebContent JIT use-after-free | iOS 26.2 / 18.7.3 | DarkSword RCE; Sekoia/APT29 campaign |
| CVE-2026-20700 | TPRO/PAC bypass | iOS 26.3 | DarkSword user-mode code execution |
| CVE-2025-14174 | ANGLE/GPU sandbox escape | iOS 26.2 / 18.7.3 | DarkSword sandbox escape |
| CVE-2025-43510 | AppleM2ScalerCSCDriver COW | iOS 26.1 / 18.7.2 | DarkSword mediaplaybackd escape |
| CVE-2025-43520 | Kernel privilege escalation | iOS 26.1 / 18.7.2 | DarkSword kernel privilege escalation |
| CVE-2024-27834 | WebKit | iOS 26.x | Cookie-theft exploit path |
| CVE-2024-4671 | WebKit | iOS 26.x | Related exploit chain |
| CVE-2025-24201 | WebKit sandbox escape | iOS 18.3.2 | DarkSword alternative sandbox escape |
| CVE-2025-31200 | CoreAudio | Unverified | DarkSword zero-click claim (unverified) |
| CVE-2026-31001 | JavaScriptCore | iOS 26.x (development) | DarkSword iOS 26 chain (not deployed) |
| CVE-2026-86950 | Apple CoreGraphics | September 2026 patch | Malicious PDF font flaw |
| CVE-2026-112607 | iOS / iPadOS / macOS | iOS 27.2 | Out-of-bounds read |
| CVE-2026-112612 | iOS / iPadOS | iOS 26.7.2 / 27.2 | Path traversal with physical access |
| CVE-2026-112507 | iOS / iPadOS | iOS 27.2 | Out-of-bounds write |
| CVE-2026-112690 | iOS / iPadOS / macOS / visionOS | iOS 27.2 | Path traversal (CVSS 10.0 critical) |

---

## 13. Detection Methodology for iPhones

### 13.1 Mobile Verification Toolkit (MVT)
MVT is the primary open-source forensic tool for iOS spyware detection. It analyzes encrypted iTunes/Finder backups and filesystem dumps.

**Installation:**
```bash
pip3 install mvt
```

**Download latest IOCs:**
```bash
mvt-ios download-iocs
```

**Check an encrypted backup:**
```bash
mvt-ios check-backup --iocs ~/iocs/pegasus.stix2 --output /path/to/output /path/to/backup
```

**Check extracted filesystem data:**
```bash
mvt-ios check-iocs --iocs ~/iocs/pegasus.stix2 /path/to/ios/output/
```

**Use iVerify STIX2 files with MVT:**
```bash
mvt-ios check-iocs --iocs ~/iocs/DarkSword.stix2 /path/to/ios/output/
mvt-ios check-iocs --iocs ~/iocs/DarkSword-Suspicious-Domains.stix2 /path/to/ios/output/
```

### 13.2 Recommended Data Sources
1. **Encrypted iTunes/Finder backup** — most reliable for non-jailbroken devices.
2. **sysdiagnose** — captures unified logs, process/network data, crash reports.
3. **Crash reports** — clusters of WebKit/GPU/kernel crashes in a short window may indicate exploit attempts.
4. **Shutdown.log / Unified logs** — iOS 26 changed `shutdown.log` handling, reducing some forensic evidence. Capture sysdiagnose **before** updating to iOS 26 if investigating older infections.
5. **Filesystem dump** (if device is jailbroken or acquired with research tools) — only way to find DarkSword filesystem artifacts.
6. **Network traffic logs** — from VPN, proxy, or DNS logs on the network perimeter (not the device itself).
7. **Safari history / WebKit databases** — DarkSword does not clean Safari history; MVT can detect initial compromise domains.

### 13.3 What to Look For
- Suspicious process names spoofing Apple daemons.
- Unknown configuration profiles or enterprise apps.
- Outbound connections to known malicious domains/IPs at odd hours.
- Multiple unexplained kernel/WebKit crashes.
- Apple Threat Notifications — treat as presumed infection; seek expert help.
- iVerify high-confidence indicators:
  - `mediaplaybackd` log messages containing `[DarkSword-WIFI-DUMP]`, `[CHAIN]`, `[MAIN]`, `[MIG_FILTER_BYPASS]`, `[TASKROP]`.
  - Filesystem artifacts in `/private/var/tmp/` such as `keychain_dump.txt`, `wifi_passwords.txt`, `p7_debug.log`, `_hq_notestore`.
- Kaspersky Triangulation indicators:
  - `BackupAgent` process in timeline.
  - `IMTransferAgent` downloading ~242 KB attachment.
  - Empty `Library/SMS/Attachments/<hex>/<hex>` directories.
  - Modified `com.apple.softwareupdateservicesd.plist` → update failures.

---

## 14. Defensive Recommendations for iOS

1. **Keep iOS Updated:** Install the latest iOS version immediately. Many 2026 exploit chains are patched in iOS 26.1/26.2/26.3/26.7.2/27.2.
2. **Enable Lockdown Mode:** For high-risk users, Apple’s Lockdown Mode significantly reduces the attack surface. Coruna specifically backs out when Lockdown Mode is detected.
3. **Enable Developer Mode:** iVerify found that Predator fails to install when iOS Developer Mode is enabled. Evaluate trade-offs (sideloading becomes easier).
4. **Avoid Sideloading / Enterprise Profiles:** Only install apps from the official App Store. Do not install developer provisioning profiles from untrusted sources.
5. **Review Photo Permissions:** Revoke photo access for apps that do not need it; avoid storing screenshots of passwords, recovery phrases, or QR codes in Photos.
6. **Use Encrypted Backups for MVT:** Regularly create encrypted iTunes/Finder backups and scan them with MVT using current STIX2 IOCs. Before updating to iOS 26, save a sysdiagnose to preserve shutdown.log evidence.
7. **Monitor Apple Threat Notifications:** If Apple alerts you to mercenary spyware targeting, assume the phone is infected and contact a forensic expert.
8. **Use Strong Account Security:** Enable Advanced Data Protection for iCloud, use hardware security keys where possible.
9. **Network-Level Controls:** Where possible, block known malicious domains/IPs at DNS or proxy level (see IOC list).
10. **Limit Safari Exposure:** Avoid visiting untrusted websites; use content blockers; be cautious of ad-based and watering-hole pages.
11. **For Website Operators:** Audit third-party tags, remove dead tags, use Content Security Policy (CSP), and monitor script changes to prevent DeadTag-style supply-chain abuse.
12. **For Ad-Tech Ecosystem:** Vet DSP/SSP partners; monitor for NOAS-style script injections; require transparency in ad creative code.

---

## 15. Full IOC List

A structured CSV version of the full IOC list is available at:
**`/Users/simon/2026_iOS_Spyware_IOC_List.csv`**

The IOCs are also available in the following scanner-ready formats:
- **MVT (Mobile Verification Toolkit) STIX2 bundle:** `/Users/simon/2026_iOS_Spyware_IOCs_MVT.stix2`
  - Use with: `mvt-ios check-backup --iocs ~/iocs/2026_iOS_Spyware_IOCs_MVT.stix2 --output /path/to/output /path/to/backup`
  - Contains 664 Indicator SDOs and 42 Vulnerability SDOs (STIX 2.1). Actionable indicator types: domains, IPs, URLs, SHA256/MD5 hashes, iOS file names, bundle IDs, and process names.
- **Nextron THOR YAML IOC file:** `/Users/simon/2026_iOS_Spyware_IOCs_THOR.yml`
  - Place in `custom-signatures/iocs/` and run THOR. Covers hashes, C2 domains/IPs, and filename indicators.
- **Nextron THOR simple IOC files:** `/Users/simon/2026_iOS_Spyware_IOCs_THOR_simple/`
  - `iOS_Spyware_c2_iocs.txt` — domain/IP indicators
  - `iOS_Spyware_hash_iocs.txt` — MD5/SHA256 file hashes
  - `iOS_Spyware_filename_iocs.txt` — filename/process indicators

**Conversion notes:**
- The CSV's non-actionable IOC types (TTPs, commands, YARA strings, log messages, crash artifacts, code names, thread names, etc.) were intentionally excluded from scanner formats because they require manual analysis or custom detection logic rather than direct pattern matching.
- File-path IOCs were converted to `file:name` patterns in STIX2 (basename only) and to plain/regex filename IOCs in THOR, which is the practical way to match iOS backup/filesystem artifacts across device-specific path prefixes.
- CVE entries were converted to STIX2 Vulnerability objects; they are not included in the THOR IOC files because THOR's IOC format does not natively support vulnerability indicators.
- The conversion script is available at `/Users/simon/convert_iocs.py` and can be re-run if the CSV is updated.

The CSV includes the following columns:
- `Malware` — family or campaign name
- `IOC_Type` — Domain, IP, URL, SHA256, MD5, BundleID, FilePath, LogMessage, Crash, YARA, STIX2, CVE, TTP, etc.
- `Indicator` — the actual IOC
- `Description` — what the IOC represents
- `Source` — reporting organization

### Notable IOC Counts (approximate)
- Pegasus: ~15 IOCs/TTPs + process/file artifacts
- Predator: ~25 IOCs/TTPs + CVEs + YARA strings
- Candiru/AdFection: ~50 domains/infrastructure indicators + 1 sample hash
- Coruna: ~120 IOCs (delivery URLs, C2s, module hashes, bundle IDs, forensic artifacts, thread names, code names, CVEs)
- DarkSword: ~460 IOCs including GHOSTBLADE/GHOSTKNIFE/GHOSTSABER/P7 hashes, C2s, filesystem artifacts, logs, crashes, YARA strings, Censys infrastructure
- SparkCat/SparkKitty: ~100 IOCs (apps, frameworks, libraries, C2s, configs, classes)
- FakeWallet: ~55 IOCs
- Packagist chain: ~45 IOCs
- Graphite: ~3 IOCs
- Operation Triangulation: ~20 IOCs
- General CVEs: ~25 CVEs

**Total: ~1,066 structured IOCs.**

---

## 16. Expanded IOCs from November 2026 Research Update

This section captures additional publicly reported indicators discovered during a follow-on research sweep of 2026 iOS spyware reporting from Google Threat Intelligence Group, iVerify, Lookout, Report URI, Socket Security, SlowMist, and Kaspersky. The corresponding structured IOCs have been merged into `/Users/simon/2026_iOS_Spyware_IOC_List.csv`.

### 16.1 DarkSword / GHOSTBLADE / GHOSTKNIFE / GHOSTSABER

Google GTIG and Lookout expanded the March 2026 DarkSword reporting with full technical details and additional IOCs:

- **Delivery domains:** `snapshare.chat` (UNC6748, Saudi Arabia), `sahibndn.io` (PARS Defense, Turkey), `e5.malaymoil.com` (PARS Defense, Malaysia), `static.cdncounter.net` / `cdncounter.net` / `cdn.cdncounter.net` / `count.cdncounter.net` (UNC6353, Ukraine).
- **C2:** `62.72.21.10`, `72.60.98.48` (UNC6748 GHOSTKNIFE); `sqwas.shapelie.com` and `141.105.130.237` (UNC6353 GHOSTBLADE).
- **Compromised Ukrainian watering holes:** `novosti.dn.ua`, `7aac.gov.ua`.
- **GHOSTBLADE sample SHA256:** `2e5a56beb63f21d9347310412ae6efb29fd3db2d3a3fc0798865a29a3c578d35`.
- **Implant classes/processes:** `GHOSTKNIFE` (JavaScript backdoor with ECDH/AES C2), `GHOSTSABER` (PARS Defense JavaScript backdoor with command dispatcher), `GHOSTBLADE` (UNC6353 dataminer injecting `powerd`, `locationd`, `imagent`, `SpringBoard`, WhatsApp).
- **GHOSTSABER commands:** `ChangeStatusCheckSleepInterval`, `SendDeviceInfo`, `SendUserAccountsList`, `SendAppList`, `ExecuteSqliteQuery`, `SendThumbnails`, `SendApp`, `SendFiles`, `SendRegEx`, `SendFileList`, `EvalJs` (some commands such as `SendCurrentLocation`, `SendScreenshot`, `SendWiFiInfo`, `RecordAudio` are referenced but not implemented in observed samples).
- **GHOSTBLADE anti-forensics:** deletes crash reports under `/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.osanalytics/DiagnosticReports/`; GHOSTKNIFE deletes `mediaplaybackd`, `SpringBoard`, `com.apple.WebKit.*`, and `panic-full-*` logs from `/var/mobile/Library/Logs/CrashReporter/`.
- **Exploit-stage filenames:** `rce_loader.js`, `frame.html`, `rce_module.js`, `rce_module_18.6.js`, `rce_module_18.7.js`, `rce_worker_18.4.js`, `rce_worker_18.5.js`, `rce_worker_18.6.js`, `rce_worker_18.7.js`, `sbx0_main_18.4.js`, `sbx0_main.js`, `sbx1_main.js`, `pe_main.js`.
- **Webpack library artifacts** left in GHOSTBLADE include paths under `src/libs/Chain/`, `src/libs/Driver/`, `src/libs/JSUtils/`, `src/libs/TaskRop/`, and `src/MigFilterBypassThread.js`.
- **YARA rules published by GTIG** for `G_Backdoor_GHOSTKNIFE_1`, `G_Backdoor_GHOSTSABER_1`, `G_Datamine_GHOSTBLADE_1`, and `G_Hunting_DarkSwordExploitChain_ImplantLib_FilePaths_1` are in the CSV.

### 16.2 DarkSword P7 Variant (iVerify)

iVerify's October 2026 P7 analysis added:

- **Delivery URLs:** `https://cdn.gotoiphone.com` and `https://mzpo30.cam/assets/js/group.html`.
- **C2:** `https://agdx53.cc` and `https://js.gotoiphone.com/ios18`.
- **Hardcoded C2 User-Agent:** iOS 18.5 Safari string.
- **Hardcoded multipart boundary:** `boundary=------HqBound` for the `/p` (photos) endpoint.
- **C2 endpoints:** `/beacon`, `/result`, `/a`, `/event`, `/u`, `/nb`, `/p`, `/war`.
- **Commands:** `execute_command`, `ls`, `download`, `photos`, `apps`, `exec`, `file_upload`, `basic_info`, `disk_scan`, `ios_app_data`, `wallet_extract`, `wallet_scan`, `memo_scan`, `photo_scan`, `sleep`, `exit`.
- **Filesystem artifacts:** `/private/var/tmp/keychain_c2_dump.json*`, `/private/var/tmp/p7_debug.log`, `/private/var/tmp/c2_wallet_debug.log`, copies of Apple Notes under `/private/var/tmp/_hq_notestore*` and `/private/var/tmp/notes.sqlite*`.

### 16.3 DeadTag Malvertising & Hijacked Analytics Tags (iVerify / Report URI)

October 2026 reporting from iVerify and Report URI found Coruna and DarkSword delivered through the ad-tech ecosystem and expired third-party tags:

- **Domain:** `ad-track.live` served a malicious Instagram ad that delivered P7 DarkSword to an enterprise iPhone.
- **TTP "DeadTag":** operators buy expired domains that previously hosted analytics/ad tags embedded on thousands of legitimate sites, then redirect iPhone visitors to exploit kits.
- **Scale:** ~135 million visits per month to sites capable of serving Coruna/DarkSword.
- **Other vectors:** PrestaShop sites had DarkSword loaders planted in fake analytics folders; a fake Polymarket page served both Coruna and P7 DarkSword.
- **Attribution clues:** Chinese-language code comments and crypto-wallet targeting (Bitpie, TronLink, OKX, Bitget) suggest a Chinese-speaking, financially motivated exploitation crew.

### 16.4 Coruna / CryptoWaters Expanded IOCs

Google GTIG and iVerify published the full Coruna exploit kit details in March 2026:

- **iVerify delivery/C2:** `mxbc-v2.tjbjdod.cn` (exploit server), `aidm8it5hf1jmtj.xyz` (config/implant), `uawwydy3qas6ykv.xyz` (C2).
- **UNC6353 delivery:** `http://cdn.uacounter.com/stat.html`.
- **UNC6691 delivery URLs:** more than 60 fake crypto/gaming sites ending in `analytics.html`, `group.html`, or `list.html` (see CSV).
- **PLASMAGRID C2 domains:** 27 DGA-style `.xyz` domains including `8fn4957c5g986jp.xyz`.
- **Implant and wallet-module hashes:** 21 SHA256 hashes for modules masquerading as `com.apple.assistd`, `com.apple.springboard`, MetaMask, Trust Wallet, Uniswap, Phantom, imToken, Bitpie, Tonkeeper, TronLink, etc.
- **Internal exploit code names:** `buffout`, `jacurutu`, `bluebird`, `terrorbird`, `cassowary`, `breezy`, `seedbell`, `IronLoader`, `NeuronLoader`, `Neutron`, `Dynamo`, `Pendulum`, `Photon`, `Parallax`, `Gruber`, `Quark`, `Gallium`, `Carbone`, `Sparrow`, `Rocket`.
- **Associated CVEs:** CVE-2021-30952, CVE-2022-48503, CVE-2023-43000, CVE-2024-23222, CVE-2023-32409, CVE-2020-27932, CVE-2020-27950, CVE-2023-32434, CVE-2023-41974, CVE-2023-38606, CVE-2024-23225, CVE-2024-23296.
- **Anti-detection:** bails out for Lockdown Mode or private browsing; uses ChaCha20-encrypted, LZW-compressed binaries in a custom `0xf00dbeef` format; DGA fallback validated via Google public DNS.
- **iVerify forensic artifacts:** thread/dispatch queue names (`plasma_*`, `helion_ipc_handler`, `com.plasma.*`), log message `failed lookup: name = com.plasma.springboard.ipc...`, static User-Agent, and `Manifest.db` file ID `98be59db1ad60b6e6e9e9d43442ce1e9e0e17b65`.

### 16.5 Packagist iOS WebKit-to-Kernel Chain Expanded IOCs

Socket Security and SlowMist added more granular IOCs for the Packagist supply-chain attack:

- **Delivery infrastructure:** `union.macoms.la`, `cdn.data-2920.com`, `cdn.data-2919.com`, `www.cloudfareintcdn.com`, `yunray.ai`, `cdn1.ai`, `nqsaaskw.com`, `abfedgecanme.com`, `abfdns.com`, `galedns.com`.
- **Exfiltration C2 domains:** 20 `www.*` domains under `.com`, `.net`, `.live`, `.info`, `.app`, `.org` (see CSV).
- **SlowMist domains:** `1k.wyincc.com`, `lk.wyincc.com`, `event.polarnode.vip`, `polarnode.vip`.
- **Exploit stage SHA256 hashes** for `lk.js`, `sandbox.html`, `vendor.js`, `runtime.js`, `runtime-legacy.js`, `polyfill.js`, `framework.js`, `framework-legacy.js`, `common.js`, `common-legacy.js`, `app.js`, `sync.js`, `auth.js`, `input.js`.

### 16.6 FakeWallet Expanded IOCs

Kaspersky's April 2026 FakeWallet report provided:

- **Ledger-specific C2:** `https://iosfc.com/ledger/ios/Rsakeycatch.php`.
- **Generic exfiltration POST path:** `/api/open/postByTokenPocket`.
- **Persistence/status files:** `verify-wallet-status.json`, `verify-wallet-config.json`, `verify-wallet-pending.json`.
- **Malicious library:** `libokexHook.dylib` injected into a modified Coinbase app to hook `RecoveryPhraseViewController.viewDidLoad`.
- **Trust Wallet variant:** custom `__hook` executable section injected before `__text`.
- **React Native Ledger tampering:** `MnemonicVerifyScreen` and `PrivateKeyVerifyScreen` navigators added to PortfolioNavigator/MyLedgerNavigator.

### 16.7 SparkCat / SparkKitty Expanded IOCs

Kaspersky's February 2025 SparkCat report included additional iOS details:

- **Malicious framework bundle ID:** `bigCat.GZIPApp`.
- **C2:** `api.aliyung.org` (HTTP) and `api.aliyung.com:18883` (Rust/TCP).
- **ComeCome iOS bundle ID:** `com.lc.btdj`.
- **Endpoints:** `/api/e/d/u`, `/api/e/config/rekognition`, `/api/e/config/keyword`, `/api/e/img/uploadedCheck`, `/api/e/img/rekognition`.
- **Native Rust library:** `libmodsvmp.so` with AES-GCM-SIV using hardcoded nonce `unique nonce`.
- **Key classes:** `MMMaker`, `ApiMgr`, `PhotoMgr`, `MMCore`, `MMLocationMgr`.

---

## 17. References

- Citizen Lab: Exposing AdFection — How Discover-Tech Turned Targeted Ads Into a Pipeline for Zero-Click Mercenary Spyware (October 2026)
- Citizen Lab: Targeting Democracy — Pegasus and Mercenary Spyware Attacks on Serbian Pro-Democracy Figures (October 2026)
- Citizen Lab: Pegasus Spyware Infection of Serbian Activist (September 2026)
- Citizen Lab: First Forensic Confirmation of Paragon’s iOS Mercenary Spyware Finds Journalists Targeted (June 2025)
- Amnesty International Security Lab: Inside Pegasus — The Evolution of the World’s Most Notorious Spyware (July 2026)
- Amnesty International Security Lab: To Catch a Predator — Leak Exposes the Internal Operations of Intellexa’s Mercenary Spyware (December 2025)
- Amnesty International Security Lab: Forensic Methodology Report — How to Catch NSO Group’s Pegasus
- Lookout: Technical Analysis of Pegasus Spyware (2016)
- iVerify: Mobile Threat Investigation Uncovers New Pegasus Samples (December 2024)
- iVerify: Key IOCs for Pegasus and Predator Spyware Cleaned With iOS 26 Update (October 2025, updated July 2026)
- iVerify: To Catch a Predator, Turn on Developer Mode (October 2023)
- iVerify: Intellexa’s Predator Exploit Chain — New Details Emerge After Google Publishes Samples (December 2025)
- iVerify: Inside DarkSword — A New iOS Exploit Kit Delivered Via Compromised Legitimate Websites (March 2026)
- iVerify: Sleep, Beacon, Steal, Repeat — The Story of P7 DarkSword Variant (October 2026)
- iVerify & Report URI: Dead Domains, Live Exploits — How Infected Ads and Expired Analytics Tags Deliver Coruna and DarkSword to iPhones (October 2026)
- iVerify: Coruna, DarkSword and the Enterprise iPhone — Key Takeaways from Packet Protector (October 2026)
- iVerify: Coruna — Inside the Nation-State-Grade iOS Exploit Kit We've Been Tracking (March 2026)
- Lookout: Attackers Wielding DarkSword Threaten iOS Users (March 2026)
- Google Cloud Blog: Coruna — The Mysterious Journey of a Powerful iOS Exploit Kit (March 2026)
- Google Cloud Blog: The Proliferation of DarkSword iOS Exploit Chain (March 2026)
- Google Cloud Blog: Sanctioned but Still Spying — Intellexa’s Prolific Zero-Day Exploits Continue (December 2025)
- Censys: DarkSword/Coruna Open Directory Finding Report (October 2026)
- Censys: DarkSword’s Panel Sprawl (July 2026)
- Sekoia: Poisoned Source — APT29 Watering Holes Target Mobile Devices with N-Day Exploits (November 2026)
- Kaspersky: SparkKitty, SparkCat’s Little Brother — A New Trojan Spy Found in the App Store and Google Play (June 2025)
- Kaspersky: New SparkCat Variant Bypassing App Store and Google Play Security (April 2026)
- Kaspersky: FakeWallet Crypto Stealer Spreading Through iOS Apps in the App Store (April 2026)
- Kaspersky: Operation Triangulation — iOS Devices Targeted with Previously Unknown Malware (June 2023)
- Socket Security: 13 Malicious Packagist Themes Deliver iOS Spyware That Steals Crypto Wallet Seeds (September 2026)
- The Hacker News: 13 Malicious Packagist Packages Target Unpatched iPhones to Steal Crypto Wallet Seeds (September 2026)
- SlowMist: Threat Intelligence — iOS Safari DarkSword Wallet Asset Theft (September 2026)
- MVT Project: Indicators of Compromise documentation
- MITRE ATT&CK: Pegasus for iOS (S0289)
- MITRE ATT&CK: Operation Triangulation (C0054)

---

**End of Report**
