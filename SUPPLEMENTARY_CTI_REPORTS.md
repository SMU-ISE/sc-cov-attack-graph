# Supplementary Material: Original CTI Report Corpus

## S1. Corpus construction and selection criteria

The evaluation corpus consists of 15 publicly accessible, English-language
cyber-threat intelligence (CTI) reports. Reports were included when they
satisfied all of the following criteria: (1) the report describes a concrete
attack campaign, intrusion, or malware operation; (2) it provides sufficient
technical detail to identify entities and directed attack relations, such as
malware, vulnerabilities, infrastructure, files, commands, victims, and threat
actors; (3) the original report or a preserved copy is publicly retrievable;
(4) the corpus collectively covers diverse actors, targets, initial-access
vectors, platforms, and attack stages; and (5) the report can be mapped
unambiguously to one AttacKG+ input and one adjudicated reference annotation.

The “selection rationale” column records the report-specific contribution to
the corpus in addition to these common eligibility criteria. Campaign names
follow the terminology used by the issuing organization. Where the publisher
did not assign a distinct campaign name, a descriptive label is used and
marked accordingly. URLs were checked on 29 July 2026. Because vendor URLs can
change, each downloaded document is also identified by a stable corpus ID and
SHA-256 digest.

## S2. Included original reports

| ID | Report title | Issuing organization | Attack campaign / operation | URL or document identifier | Selection rationale |
|---|---|---|---|---|---|
| CTI-01 | *Early Bird Catches the Wormhole: Observations from the StellarParticle Campaign* | CrowdStrike | StellarParticle; associated with COZY BEAR/APT29 and the SolarWinds/SUNSPOT activity cluster | [Original report](https://www.crowdstrike.com/en-us/blog/observations-from-the-stellarparticle-campaign/); SHA-256 `47ee9473986c45d58e0a041b10ed1a56aed0f22caa15dfd2e55fdc8b7001fd1a` | Included as a complex supply-chain and cloud-identity intrusion containing credential hopping, MFA bypass, O365 service-principal abuse, and multiple malware families. |
| CTI-02 | *Asylum Ambuscade: State Actor Uses Compromised Private Ukrainian Military Emails to Target European Governments and Refugee Movement* | Proofpoint | Asylum Ambuscade; possible TA445/UNC1151-related phishing activity, without definitive attribution by Proofpoint | [Original report](https://www.proofpoint.com/uk/blog/threat-insight/asylum-ambuscade-state-actor-uses-compromised-private-ukrainian-military-emails); SHA-256 `7ca0553d100b7c9b407faa195340a4149b5fe89d752e13a38e040fa99e1a1734` | Included for its clearly documented phishing chain using a compromised military mailbox, a macro-enabled spreadsheet, and SunSeed malware against European government personnel. |
| CTI-03 | *BRONZE PRESIDENT Targets Government Officials* | Secureworks Counter Threat Unit | BRONZE PRESIDENT PlugX campaign targeting government officials | [Canonical vendor URL](https://www.secureworks.com/blog/bronze-president-targets-government-officials); preserved PDF `0903ff6d3b598d56dc8806ebcbd48aa27a1f5df4`; SHA-256 `af8899f2ad42a89b7876c77e5d3dd7f6b638cb177b4a855d04dbdb558d7da282` | Included for a government-focused espionage chain with spear phishing, PlugX deployment, persistence, infrastructure, and attribution evidence. |
| CTI-04 | *SK Hack by an Advanced Persistent Threat* | Command Five Pty Ltd | July 2011 SK Communications intrusion (“SK Hack”); actor not conclusively named | [Preserved PDF](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2013/04/20082912/C5_APT_SKHack.pdf); original document name `C5_APT_SKHack.pdf`; SHA-256 `5c3e2df657d16062ea59791a2d330c08fda778d31e1e7e7fbfae51be74705446` | Included as an early software-update/supply-chain compromise that led to database access and large-scale theft of CyWorld and Nate user information. |
| CTI-05 | *Bitter APT Adds Bangladesh to Their Targets* | Cisco Talos | Bitter APT/T-APT-17 Bangladesh campaign | [Original report](https://blog.talosintelligence.com/bitter-apt-adds-bangladesh-to-their/); SHA-256 `72d4b98982d89b28962b64642f95fba5d73b5f114dc6dd1daa2e945a6bd8d29a` | Included for a South Asian government-targeting campaign containing weaponized RTF/XLS documents, multiple Microsoft Office CVEs, shellcode, downloaders, and RAT behavior. |
| CTI-06 | *Iranian APT MuddyWater Targets Turkish Users via Malicious PDFs, Executables* | Cisco Talos | MuddyWater campaign targeting Turkish government and private organizations | [Original report](https://blog.talosintelligence.com/iranian-apt-muddywater-targets-turkey/); SHA-256 `92adb88cde460193abd63ce6942b82dacdd0ed1ba9a5635d6d50b3805dc71b6f` | Included for heterogeneous initial-access artifacts—PDF, XLS, and executables—and PowerShell downloaders, canary tokens, and attributed Iranian espionage activity. |
| CTI-07 | *Iron Tiger Compromises Chat Application MiMi, Targets Windows, Mac, and Linux Users* | Trend Micro | Iron Tiger/APT27 MiMi supply-chain compromise | [Original report](https://www.trendmicro.com/en_us/research/22/h/irontiger-compromises-chat-app-Mimi-targets-windows-mac-linux-users.html); SHA-256 `33987e302441f7bb4c542544dbabff1fa00dccac7bbab926c300203261155c60` | Included to represent a cross-platform supply-chain attack in which legitimate chat-application infrastructure delivered HyperBro and rshell payloads to Windows, macOS, and Linux targets. |
| CTI-08 | *MoonBounce: The Dark Side of UEFI Firmware* | Kaspersky Global Research and Analysis Team / Securelist | MoonBounce UEFI implant operation; assessed as connected to APT41 | [Original report](https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/); Securelist article ID `105468`; SHA-256 `ea7e3eb7ff4e0d4e26f81d2472c2476f30e7107c4287f417cdd1836c017b3954` | Included for firmware-level persistence and a technically distinct execution chain spanning UEFI, user-mode staging, malware, and command-and-control components. |
| CTI-09 | *Mustang Panda’s Hodur: Old Tricks, New Korplug Variant* | ESET Research / WeLiveSecurity | Mustang Panda Hodur campaign | [Original report](https://www.welivesecurity.com/2022/03/23/mustang-panda-hodur-old-tricks-new-korplug-variant/); SHA-256 `ec6d744ac06b1c23714761c2f25dbf2767d7cb1f4ece7d19a1bf56d2d41d4602` | Included for a well-scoped spear-phishing and custom-loader chain deploying the previously undocumented Hodur/Korplug variant with anti-analysis behavior. |
| CTI-10 | *New Milestones for Deep Panda: Log4Shell and Digitally Signed Fire Chili Rootkits* | Fortinet FortiGuard Labs | Deep Panda Log4Shell campaign deploying the Milestone backdoor and Fire Chili rootkit | [Original report](https://www.fortinet.com/blog/threat-research/deep-panda-log4shell-fire-chili-rootkits); SHA-256 `5c9c73de770b491c8ae1088a6d1fb5394c694e5b7e1fdd5eab51de7255a4ad7b` | Included for an exploit-to-rootkit chain linking CVE-2021-44228 exploitation, a backdoor, a signed kernel rootkit, certificate abuse, and actor attribution. |
| CTI-11 | *North Korea’s Lazarus APT Leverages Windows Update Client, GitHub in Latest Campaign* | Malwarebytes Threat Intelligence | Lazarus job-opportunity spear-phishing campaign, late 2021–early 2022 | [Original report](https://www.malwarebytes.com/blog/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign); SHA-256 `9d030af0c272b28e0a87f6081e81c80bb75cd5f2225bfb0c5564fb644f9372bd` | Included for its documented malicious-document chain and unusual abuse of the Windows Update client for execution and GitHub for command and control. |
| CTI-12 | *Prime Minister’s Office Compromised: Details of Recent Espionage Campaign* | Trellix Advanced Threat Research | Multi-stage Graphite/Empire espionage campaign; moderately associated by Trellix with APT28 | [Original report](https://www.trellix.com/blogs/research/prime-ministers-office-compromised/); SHA-256 `ec2e38dbf8d3399ca49e5a59602f2216aff55150c5a88c64b7497f6af302b1d8` | Included for a full multi-stage chain combining CVE-2021-40444, an Excel lure, Graphite, Microsoft Graph/OneDrive C2, COM hijacking, and Empire. |
| CTI-13 | *Shuckworm: Espionage Group Continues Intense Campaign Against Ukraine* | Symantec Threat Hunter Team | Shuckworm/Gamaredon/Armageddon campaign against Ukrainian organizations | [Original report](https://www.security.com/threat-intelligence/shuckworm-intense-campaign-ukraine); SHA-256 `82622d7482a16bbe4954f8284c82b5c01c4092da71bb8ef75e29a6a86ece9711` | Included to cover a high-frequency regional espionage operation with repeated Pterodo deployment and use of legitimate administration and diagnostic utilities. |
| CTI-14 | *Stuxnet Under the Microscope* | ESET | Stuxnet operation targeting Siemens industrial-control environments | [Original PDF](https://web-assets.esetstatic.com/wls/en/papers/white-papers/Stuxnet_Under_the_Microscope.pdf); document name `Stuxnet_Under_the_Microscope.pdf`; SHA-256 `dbb6bcbbc8a0b05f9fa4e0b70a7ebe80b4d5f68e918d5e11f2d67db69c7a7f75` | Included as a canonical industrial-control-system case with multiple exploits, propagation mechanisms, rootkit behavior, Siemens/SCADA targeting, and a detailed technical timeline. |
| CTI-15 | *The Nitro Attacks: Stealing Secrets from the Chemical Industry* | Symantec Security Response | Nitro targeted-attack campaign | [Preserved PDF](https://scadahacker.com/library/Documents/Cyber_Events/Symantec%20-%20The%20Nitro%20Attacks.pdf); document title `The Nitro Attacks`; SHA-256 `eebe884304e69c2b4bae34cb76c8ed8bcb073e5d8e46fa1456d488d4a8ba91d9` | Included to represent industrial espionage against chemical and advanced-material organizations, with targeted email delivery, PoisonIvy, credential theft, lateral movement, staging, and exfiltration. |

## S3. Reproducibility notes

Four reports were acquired as PDFs (CTI-03, CTI-04, CTI-14, and CTI-15);
the remaining reports were captured as HTML. The SHA-256 digest is calculated
over the downloaded raw file, not the extracted text. The acquisition manifest,
including download time, final resolved URL, format, file size, and local paths,
is provided in `evaluation/corpus/downloaded/manifest.json`. The corpus table is
also distributed as `evaluation/SUPPLEMENTARY_CTI_REPORTS.csv` for direct reuse
in spreadsheet and typesetting workflows.

