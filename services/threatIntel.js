// Curated threat intelligence database: CVE → Threat Actors, Incidents, Targeted Sectors
// Based on publicly documented reports from CISA, MITRE ATT&CK, vendor advisories, and threat intel feeds.

const SECTORS = [
  'Government', 'Defense', 'Finance', 'Healthcare', 'Energy',
  'Technology', 'Telecom', 'Education', 'Manufacturing', 'Retail',
  'Media', 'Transportation', 'Legal', 'Aerospace',
];

// Heat levels: 0=none, 1=low, 2=medium, 3=high, 4=very-high, 5=critical (confirmed breaches)
const CVE_THREAT_DB = {

  'CVE-2021-44228': {
    name: 'Log4Shell',
    actors: [
      { name: 'APT41', aliases: ['Double Dragon', 'Winnti'], origin: 'China', motivation: 'Espionage, Financial', first_seen: '2021-12' },
      { name: 'Lazarus Group', aliases: ['HIDDEN COBRA', 'Zinc'], origin: 'North Korea', motivation: 'Financial, Espionage', first_seen: '2021-12' },
      { name: 'Aquatic Panda', aliases: [], origin: 'China', motivation: 'Espionage', first_seen: '2021-12' },
      { name: 'PHOSPHORUS', aliases: ['Charming Kitten', 'APT35'], origin: 'Iran', motivation: 'Espionage, Ransomware', first_seen: '2022-01' },
      { name: 'Prophet Spider', aliases: [], origin: 'Unknown', motivation: 'Financial (Ransomware)', first_seen: '2021-12' },
      { name: 'Conti', aliases: [], origin: 'Russia', motivation: 'Financial (Ransomware)', first_seen: '2021-12' },
    ],
    incidents: [
      { name: 'Belgian Ministry of Defense', date: '2021-12', type: 'Government Breach', impact: 'Network compromise and email shutdown' },
      { name: 'VMware Horizon mass exploitation', date: '2022-01', type: 'Mass Exploitation', impact: 'Thousands of servers compromised globally' },
      { name: 'Crypto mining campaigns', date: '2021-12', type: 'Cryptojacking', impact: 'Large-scale coin miner deployment' },
    ],
    sectors: { Government: 5, Defense: 4, Finance: 5, Healthcare: 4, Energy: 4, Technology: 5, Telecom: 4, Education: 3, Manufacturing: 3, Retail: 2, Media: 2, Transportation: 2, Legal: 1, Aerospace: 2 },
  },

  'CVE-2021-26855': {
    name: 'ProxyLogon',
    actors: [
      { name: 'HAFNIUM', aliases: ['Silk Typhoon'], origin: 'China', motivation: 'Espionage', first_seen: '2021-01' },
      { name: 'APT27', aliases: ['LuckyMouse', 'Emissary Panda'], origin: 'China', motivation: 'Espionage', first_seen: '2021-03' },
      { name: 'Calypso APT', aliases: [], origin: 'China', motivation: 'Espionage', first_seen: '2021-03' },
      { name: 'Tick', aliases: ['Bronze Butler'], origin: 'China', motivation: 'Espionage', first_seen: '2021-03' },
      { name: 'DearCry', aliases: ['DoejoCrypt'], origin: 'Unknown', motivation: 'Financial (Ransomware)', first_seen: '2021-03' },
    ],
    incidents: [
      { name: '30,000+ Exchange servers breached', date: '2021-03', type: 'Mass Exploitation', impact: 'Global zero-day exploitation wave' },
      { name: 'European Banking Authority', date: '2021-03', type: 'Financial Breach', impact: 'Email server compromise' },
      { name: 'Norwegian Parliament', date: '2021-03', type: 'Government Breach', impact: 'Data exfiltration from email accounts' },
    ],
    sectors: { Government: 5, Defense: 4, Finance: 5, Healthcare: 3, Energy: 3, Technology: 5, Telecom: 3, Education: 4, Manufacturing: 2, Retail: 1, Media: 1, Transportation: 1, Legal: 3, Aerospace: 2 },
  },

  'CVE-2021-27065': {
    name: 'ProxyLogon (RCE)',
    actors: [
      { name: 'HAFNIUM', aliases: ['Silk Typhoon'], origin: 'China', motivation: 'Espionage', first_seen: '2021-01' },
      { name: 'APT27', aliases: ['LuckyMouse'], origin: 'China', motivation: 'Espionage', first_seen: '2021-03' },
    ],
    incidents: [
      { name: 'Chained with CVE-2021-26855', date: '2021-03', type: 'Mass Exploitation', impact: 'Web shell deployment on Exchange servers' },
    ],
    sectors: { Government: 5, Defense: 4, Finance: 4, Healthcare: 3, Energy: 3, Technology: 5, Telecom: 3, Education: 3, Manufacturing: 2, Retail: 1, Media: 1, Transportation: 1, Legal: 3, Aerospace: 2 },
  },

  'CVE-2023-34362': {
    name: 'MOVEit Transfer SQLi',
    actors: [
      { name: 'Cl0p', aliases: ['FIN11', 'TA505', 'Lace Tempest'], origin: 'Russia', motivation: 'Financial (Extortion)', first_seen: '2023-05' },
    ],
    incidents: [
      { name: 'BBC & British Airways (Zellis payroll)', date: '2023-06', type: 'Data Breach', impact: 'Employee personal data exfiltrated' },
      { name: 'US Government agencies (DoE, OPM)', date: '2023-06', type: 'Government Breach', impact: 'Federal agency data compromised' },
      { name: 'Shell', date: '2023-06', type: 'Corporate Breach', impact: 'Employee data stolen' },
      { name: '2,500+ organizations impacted', date: '2023-06', type: 'Mass Exploitation', impact: '60M+ individuals affected globally' },
    ],
    sectors: { Government: 5, Defense: 3, Finance: 5, Healthcare: 5, Energy: 4, Technology: 4, Telecom: 3, Education: 5, Manufacturing: 3, Retail: 3, Media: 4, Transportation: 2, Legal: 3, Aerospace: 2 },
  },

  'CVE-2023-4966': {
    name: 'Citrix Bleed',
    actors: [
      { name: 'LockBit 3.0', aliases: ['Bitwise Spider'], origin: 'Russia', motivation: 'Financial (Ransomware)', first_seen: '2023-10' },
      { name: 'Medusa', aliases: [], origin: 'Unknown', motivation: 'Financial (Ransomware)', first_seen: '2023-11' },
      { name: 'AlphV', aliases: ['BlackCat'], origin: 'Russia', motivation: 'Financial (Ransomware)', first_seen: '2023-11' },
    ],
    incidents: [
      { name: 'Boeing', date: '2023-11', type: 'Aerospace Breach', impact: 'Data leaked by LockBit' },
      { name: 'ICBC Financial Services', date: '2023-11', type: 'Financial Breach', impact: 'US Treasury trading disrupted' },
      { name: 'Allen & Overy (law firm)', date: '2023-11', type: 'Corporate Breach', impact: 'Data breach confirmed' },
      { name: 'DP World Australia', date: '2023-11', type: 'Transportation Breach', impact: 'Port operations suspended' },
    ],
    sectors: { Government: 3, Defense: 2, Finance: 5, Healthcare: 3, Energy: 2, Technology: 4, Telecom: 3, Education: 1, Manufacturing: 3, Retail: 2, Media: 1, Transportation: 5, Legal: 4, Aerospace: 5 },
  },

  'CVE-2023-23397': {
    name: 'Outlook Elevation of Privilege',
    actors: [
      { name: 'APT28', aliases: ['Fancy Bear', 'Forest Blizzard', 'Sofacy'], origin: 'Russia (GRU)', motivation: 'Espionage', first_seen: '2022-04' },
    ],
    incidents: [
      { name: 'European government agencies', date: '2022-04', type: 'Espionage Campaign', impact: 'NTLM credential theft via crafted emails' },
      { name: 'NATO-affiliated entities', date: '2023-03', type: 'Espionage Campaign', impact: 'Targeted spear-phishing with zero-click exploit' },
      { name: 'Ukrainian organizations', date: '2022-04', type: 'Espionage Campaign', impact: 'Credential theft during conflict' },
    ],
    sectors: { Government: 5, Defense: 5, Finance: 2, Healthcare: 1, Energy: 4, Technology: 2, Telecom: 2, Education: 1, Manufacturing: 1, Retail: 0, Media: 2, Transportation: 3, Legal: 1, Aerospace: 2 },
  },

  'CVE-2024-3400': {
    name: 'PAN-OS Command Injection',
    actors: [
      { name: 'UTA0218', aliases: [], origin: 'Unknown (State-sponsored)', motivation: 'Espionage', first_seen: '2024-03' },
    ],
    incidents: [
      { name: 'Global firewall exploitation campaign', date: '2024-04', type: 'Mass Exploitation', impact: 'Reverse shells deployed on PAN-OS devices' },
    ],
    sectors: { Government: 4, Defense: 4, Finance: 3, Healthcare: 2, Energy: 3, Technology: 5, Telecom: 3, Education: 2, Manufacturing: 2, Retail: 1, Media: 1, Transportation: 1, Legal: 1, Aerospace: 2 },
  },

  'CVE-2020-1472': {
    name: 'Zerologon',
    actors: [
      { name: 'APT10', aliases: ['menuPass', 'Stone Panda'], origin: 'China', motivation: 'Espionage', first_seen: '2020-09' },
      { name: 'Mercury', aliases: ['MuddyWater', 'Static Kitten'], origin: 'Iran (MOIS)', motivation: 'Espionage', first_seen: '2020-10' },
      { name: 'Ryuk', aliases: ['Wizard Spider'], origin: 'Russia', motivation: 'Financial (Ransomware)', first_seen: '2020-09' },
      { name: 'TA505', aliases: ['Cl0p affiliate'], origin: 'Russia', motivation: 'Financial', first_seen: '2020-10' },
    ],
    incidents: [
      { name: 'Hospital network ransomware attacks', date: '2020-10', type: 'Healthcare Breach', impact: 'Hospital systems encrypted during COVID-19' },
      { name: 'US government agency domain compromise', date: '2020-09', type: 'Government Breach', impact: 'Active Directory takeover' },
    ],
    sectors: { Government: 5, Defense: 3, Finance: 4, Healthcare: 5, Energy: 3, Technology: 4, Telecom: 2, Education: 4, Manufacturing: 3, Retail: 2, Media: 1, Transportation: 1, Legal: 2, Aerospace: 1 },
  },

  'CVE-2019-19781': {
    name: 'Citrix ADC Path Traversal',
    actors: [
      { name: 'APT41', aliases: ['Double Dragon', 'Winnti'], origin: 'China', motivation: 'Espionage, Financial', first_seen: '2020-01' },
      { name: 'Fox Kitten', aliases: ['Pioneer Kitten', 'Parisite'], origin: 'Iran', motivation: 'Espionage, Access Broker', first_seen: '2020-01' },
      { name: 'REvil', aliases: ['Sodinokibi'], origin: 'Russia', motivation: 'Financial (Ransomware)', first_seen: '2020-01' },
    ],
    incidents: [
      { name: 'Mass scanning and exploitation', date: '2020-01', type: 'Mass Exploitation', impact: 'Thousands of Citrix ADC devices compromised' },
    ],
    sectors: { Government: 4, Defense: 3, Finance: 4, Healthcare: 3, Energy: 3, Technology: 4, Telecom: 3, Education: 2, Manufacturing: 3, Retail: 2, Media: 1, Transportation: 2, Legal: 2, Aerospace: 1 },
  },

  'CVE-2022-27518': {
    name: 'Citrix ADC RCE',
    actors: [
      { name: 'APT5', aliases: ['UNC2630', 'Manganese'], origin: 'China', motivation: 'Espionage', first_seen: '2022-12' },
    ],
    incidents: [
      { name: 'NSA advisory on active exploitation', date: '2022-12', type: 'Espionage Campaign', impact: 'Telecom and government targeting' },
    ],
    sectors: { Government: 5, Defense: 4, Finance: 2, Healthcare: 1, Energy: 2, Technology: 4, Telecom: 5, Education: 1, Manufacturing: 2, Retail: 0, Media: 0, Transportation: 1, Legal: 0, Aerospace: 2 },
  },

  'CVE-2023-46805': {
    name: 'Ivanti Connect Secure Auth Bypass',
    actors: [
      { name: 'UTA0178', aliases: [], origin: 'China (suspected)', motivation: 'Espionage', first_seen: '2023-12' },
      { name: 'UTA0188', aliases: [], origin: 'Unknown', motivation: 'Unknown', first_seen: '2024-01' },
      { name: 'Volt Typhoon', aliases: ['Bronze Silhouette'], origin: 'China', motivation: 'Pre-positioning', first_seen: '2024-01' },
    ],
    incidents: [
      { name: 'CISA network breach', date: '2024-02', type: 'Government Breach', impact: 'CISA took two systems offline' },
      { name: 'MITRE Corporation breach', date: '2024-01', type: 'Research Breach', impact: 'Network compromise via Ivanti VPN' },
    ],
    sectors: { Government: 5, Defense: 5, Finance: 3, Healthcare: 2, Energy: 3, Technology: 4, Telecom: 3, Education: 2, Manufacturing: 1, Retail: 0, Media: 0, Transportation: 1, Legal: 1, Aerospace: 3 },
  },

  'CVE-2024-21887': {
    name: 'Ivanti Connect Secure Command Injection',
    actors: [
      { name: 'UTA0178', aliases: [], origin: 'China (suspected)', motivation: 'Espionage', first_seen: '2023-12' },
      { name: 'Volt Typhoon', aliases: ['Bronze Silhouette'], origin: 'China', motivation: 'Pre-positioning', first_seen: '2024-01' },
    ],
    incidents: [
      { name: 'Chained with CVE-2023-46805', date: '2024-01', type: 'Mass Exploitation', impact: 'Web shells deployed on VPN appliances' },
    ],
    sectors: { Government: 5, Defense: 5, Finance: 3, Healthcare: 2, Energy: 3, Technology: 4, Telecom: 3, Education: 2, Manufacturing: 1, Retail: 0, Media: 0, Transportation: 1, Legal: 1, Aerospace: 3 },
  },

  'CVE-2021-34473': {
    name: 'ProxyShell',
    actors: [
      { name: 'Conti', aliases: ['Wizard Spider'], origin: 'Russia', motivation: 'Financial (Ransomware)', first_seen: '2021-08' },
      { name: 'LockFile', aliases: [], origin: 'Unknown', motivation: 'Financial (Ransomware)', first_seen: '2021-08' },
      { name: 'Various APTs', aliases: [], origin: 'Multiple', motivation: 'Espionage', first_seen: '2021-08' },
    ],
    incidents: [
      { name: 'Mass Exchange exploitation wave', date: '2021-08', type: 'Mass Exploitation', impact: 'Web shells on unpatched Exchange servers' },
    ],
    sectors: { Government: 4, Defense: 3, Finance: 4, Healthcare: 3, Energy: 3, Technology: 4, Telecom: 3, Education: 3, Manufacturing: 2, Retail: 1, Media: 1, Transportation: 1, Legal: 2, Aerospace: 1 },
  },

  'CVE-2017-11882': {
    name: 'Office Equation Editor Stack Overflow',
    actors: [
      { name: 'APT28', aliases: ['Fancy Bear', 'Sofacy'], origin: 'Russia (GRU)', motivation: 'Espionage', first_seen: '2017-12' },
      { name: 'APT34', aliases: ['OilRig', 'Helix Kitten'], origin: 'Iran', motivation: 'Espionage', first_seen: '2018-01' },
      { name: 'Cobalt Group', aliases: ['Cobalt Gang'], origin: 'Unknown', motivation: 'Financial', first_seen: '2017-12' },
      { name: 'SideWinder', aliases: ['Rattlesnake'], origin: 'India', motivation: 'Espionage', first_seen: '2018-03' },
    ],
    incidents: [
      { name: 'Global spear-phishing campaigns', date: '2017-12', type: 'Espionage Campaign', impact: 'Weaponized Office documents distributed worldwide' },
    ],
    sectors: { Government: 5, Defense: 4, Finance: 5, Healthcare: 1, Energy: 3, Technology: 3, Telecom: 2, Education: 2, Manufacturing: 1, Retail: 1, Media: 2, Transportation: 1, Legal: 1, Aerospace: 2 },
  },

  'CVE-2018-13379': {
    name: 'FortiOS SSL VPN Path Traversal',
    actors: [
      { name: 'APT29', aliases: ['Cozy Bear', 'Midnight Blizzard'], origin: 'Russia (SVR)', motivation: 'Espionage', first_seen: '2020-07' },
      { name: 'Cring', aliases: ['Crypt3r'], origin: 'Unknown', motivation: 'Financial (Ransomware)', first_seen: '2021-01' },
      { name: 'Various Iranian APTs', aliases: [], origin: 'Iran', motivation: 'Espionage, Access Broker', first_seen: '2020-09' },
    ],
    incidents: [
      { name: 'Credentials of 500K FortiGate devices leaked', date: '2021-09', type: 'Credential Leak', impact: 'Plaintext VPN credentials posted on dark web' },
      { name: 'FBI/CISA joint advisory', date: '2021-04', type: 'Mass Exploitation', impact: 'APT actors scanning and exploiting globally' },
    ],
    sectors: { Government: 5, Defense: 3, Finance: 4, Healthcare: 3, Energy: 4, Technology: 4, Telecom: 3, Education: 2, Manufacturing: 3, Retail: 1, Media: 1, Transportation: 2, Legal: 1, Aerospace: 1 },
  },

  'CVE-2022-42475': {
    name: 'FortiOS SSL VPN Heap Overflow',
    actors: [
      { name: 'Volt Typhoon', aliases: ['Bronze Silhouette', 'Vanguard Panda'], origin: 'China', motivation: 'Pre-positioning, Espionage', first_seen: '2022-11' },
    ],
    incidents: [
      { name: 'Government and critical infrastructure targeting', date: '2022-12', type: 'Espionage Campaign', impact: 'Persistent access to network edge devices' },
    ],
    sectors: { Government: 5, Defense: 4, Finance: 2, Healthcare: 1, Energy: 4, Technology: 3, Telecom: 4, Education: 1, Manufacturing: 2, Retail: 0, Media: 0, Transportation: 3, Legal: 0, Aerospace: 1 },
  },

  'CVE-2024-21762': {
    name: 'FortiOS Out-of-Bound Write',
    actors: [
      { name: 'Volt Typhoon', aliases: ['Bronze Silhouette'], origin: 'China', motivation: 'Pre-positioning', first_seen: '2024-02' },
    ],
    incidents: [
      { name: 'Critical infrastructure pre-positioning', date: '2024-02', type: 'Espionage Campaign', impact: 'Living-off-the-land persistence on network devices' },
    ],
    sectors: { Government: 5, Defense: 4, Finance: 2, Healthcare: 1, Energy: 5, Technology: 3, Telecom: 4, Education: 1, Manufacturing: 2, Retail: 0, Media: 0, Transportation: 4, Legal: 0, Aerospace: 1 },
  },

  'CVE-2023-22515': {
    name: 'Atlassian Confluence Privilege Escalation',
    actors: [
      { name: 'Storm-0062', aliases: ['DarkShadow', 'Oro0lxy'], origin: 'China', motivation: 'Espionage', first_seen: '2023-09' },
    ],
    incidents: [
      { name: 'Active exploitation before disclosure', date: '2023-10', type: 'Zero-day Campaign', impact: 'Unauthorized admin account creation' },
    ],
    sectors: { Government: 4, Defense: 2, Finance: 3, Healthcare: 1, Energy: 2, Technology: 5, Telecom: 2, Education: 2, Manufacturing: 2, Retail: 1, Media: 1, Transportation: 0, Legal: 1, Aerospace: 1 },
  },

  'CVE-2024-1709': {
    name: 'ConnectWise ScreenConnect Auth Bypass',
    actors: [
      { name: 'Black Basta', aliases: [], origin: 'Russia', motivation: 'Financial (Ransomware)', first_seen: '2024-02' },
      { name: 'LockBit', aliases: ['Bitwise Spider'], origin: 'Russia', motivation: 'Financial (Ransomware)', first_seen: '2024-02' },
    ],
    incidents: [
      { name: 'Mass ransomware deployment', date: '2024-02', type: 'Mass Exploitation', impact: 'MSP clients compromised through RMM tool' },
    ],
    sectors: { Government: 3, Defense: 1, Finance: 3, Healthcare: 4, Energy: 2, Technology: 5, Telecom: 2, Education: 3, Manufacturing: 2, Retail: 2, Media: 1, Transportation: 1, Legal: 2, Aerospace: 0 },
  },

  'CVE-2021-34527': {
    name: 'PrintNightmare',
    actors: [
      { name: 'Vice Society', aliases: [], origin: 'Unknown', motivation: 'Financial (Ransomware)', first_seen: '2021-07' },
      { name: 'Magniber', aliases: [], origin: 'North Korea (suspected)', motivation: 'Financial (Ransomware)', first_seen: '2021-07' },
    ],
    incidents: [
      { name: 'Education and healthcare ransomware wave', date: '2021-07', type: 'Mass Exploitation', impact: 'Print spooler exploited for domain compromise' },
    ],
    sectors: { Government: 4, Defense: 2, Finance: 3, Healthcare: 5, Energy: 2, Technology: 4, Telecom: 2, Education: 5, Manufacturing: 2, Retail: 1, Media: 1, Transportation: 1, Legal: 1, Aerospace: 1 },
  },

  'CVE-2023-0669': {
    name: 'GoAnywhere MFT RCE',
    actors: [
      { name: 'Cl0p', aliases: ['FIN11', 'TA505'], origin: 'Russia', motivation: 'Financial (Extortion)', first_seen: '2023-01' },
    ],
    incidents: [
      { name: '130+ organizations breached', date: '2023-02', type: 'Mass Exploitation', impact: 'Data exfiltration and extortion campaign' },
      { name: 'Community Health Systems', date: '2023-02', type: 'Healthcare Breach', impact: '1M patient records compromised' },
    ],
    sectors: { Government: 3, Defense: 1, Finance: 4, Healthcare: 5, Energy: 3, Technology: 3, Telecom: 2, Education: 2, Manufacturing: 2, Retail: 2, Media: 1, Transportation: 1, Legal: 2, Aerospace: 1 },
  },

  'CVE-2017-0199': {
    name: 'Office/WordPad RCE',
    actors: [
      { name: 'APT28', aliases: ['Fancy Bear'], origin: 'Russia (GRU)', motivation: 'Espionage', first_seen: '2017-04' },
      { name: 'APT34', aliases: ['OilRig'], origin: 'Iran', motivation: 'Espionage', first_seen: '2017-05' },
      { name: 'Cobalt Group', aliases: [], origin: 'Unknown', motivation: 'Financial', first_seen: '2017-04' },
      { name: 'Dridex operators', aliases: [], origin: 'Eastern Europe', motivation: 'Financial (Banking Trojan)', first_seen: '2017-04' },
    ],
    incidents: [
      { name: 'Global phishing campaigns with weaponized RTF', date: '2017-04', type: 'Mass Exploitation', impact: 'Widely adopted by crimeware and APTs alike' },
    ],
    sectors: { Government: 5, Defense: 4, Finance: 5, Healthcare: 2, Energy: 3, Technology: 3, Telecom: 2, Education: 2, Manufacturing: 1, Retail: 2, Media: 2, Transportation: 1, Legal: 1, Aerospace: 2 },
  },

  'CVE-2019-0708': {
    name: 'BlueKeep',
    actors: [
      { name: 'Cryptomining campaigns', aliases: [], origin: 'Multiple', motivation: 'Financial (Cryptojacking)', first_seen: '2019-11' },
    ],
    incidents: [
      { name: 'NSA advisory and global scanning', date: '2019-05', type: 'Mass Exploitation', impact: 'Wormable RDP vulnerability affecting Windows XP-7/Server 2008' },
    ],
    sectors: { Government: 4, Defense: 2, Finance: 3, Healthcare: 4, Energy: 2, Technology: 3, Telecom: 2, Education: 3, Manufacturing: 3, Retail: 2, Media: 1, Transportation: 2, Legal: 1, Aerospace: 1 },
  },

  'CVE-2023-27997': {
    name: 'FortiOS XORtigate Heap Overflow',
    actors: [
      { name: 'Volt Typhoon', aliases: ['Bronze Silhouette'], origin: 'China', motivation: 'Pre-positioning', first_seen: '2023-06' },
    ],
    incidents: [
      { name: 'Critical infrastructure targeting', date: '2023-06', type: 'Espionage Campaign', impact: 'VPN appliance exploitation for network access' },
    ],
    sectors: { Government: 5, Defense: 4, Finance: 2, Healthcare: 1, Energy: 4, Technology: 3, Telecom: 4, Education: 1, Manufacturing: 2, Retail: 0, Media: 0, Transportation: 3, Legal: 0, Aerospace: 1 },
  },

  'CVE-2022-41040': {
    name: 'ProxyNotShell (SSRF)',
    actors: [
      { name: 'Play Ransomware', aliases: ['PlayCrypt'], origin: 'Unknown', motivation: 'Financial (Ransomware)', first_seen: '2022-11' },
      { name: 'Various state-sponsored', aliases: [], origin: 'Multiple', motivation: 'Espionage', first_seen: '2022-09' },
    ],
    incidents: [
      { name: 'Exchange zero-day exploitation', date: '2022-09', type: 'Zero-day Campaign', impact: 'PowerShell web shells deployed' },
    ],
    sectors: { Government: 4, Defense: 2, Finance: 3, Healthcare: 2, Energy: 2, Technology: 4, Telecom: 2, Education: 2, Manufacturing: 2, Retail: 1, Media: 1, Transportation: 1, Legal: 2, Aerospace: 1 },
  },

  'CVE-2021-40444': {
    name: 'MSHTML RCE',
    actors: [
      { name: 'Wizard Spider', aliases: ['TrickBot operators'], origin: 'Russia', motivation: 'Financial', first_seen: '2021-09' },
      { name: 'DEV-0365', aliases: [], origin: 'Unknown', motivation: 'Financial', first_seen: '2021-09' },
    ],
    incidents: [
      { name: 'Weaponized Office documents in phishing', date: '2021-09', type: 'Espionage Campaign', impact: 'Zero-day exploited before patch available' },
    ],
    sectors: { Government: 4, Defense: 3, Finance: 3, Healthcare: 1, Energy: 2, Technology: 3, Telecom: 2, Education: 2, Manufacturing: 1, Retail: 1, Media: 1, Transportation: 1, Legal: 2, Aerospace: 2 },
  },

  'CVE-2023-20198': {
    name: 'Cisco IOS XE Web UI Privilege Escalation',
    actors: [
      { name: 'Unknown state-sponsored', aliases: [], origin: 'Unknown', motivation: 'Espionage', first_seen: '2023-10' },
    ],
    incidents: [
      { name: '40,000+ devices compromised', date: '2023-10', type: 'Mass Exploitation', impact: 'Backdoor implants on Cisco network devices' },
    ],
    sectors: { Government: 5, Defense: 3, Finance: 3, Healthcare: 2, Energy: 3, Technology: 4, Telecom: 5, Education: 3, Manufacturing: 2, Retail: 1, Media: 1, Transportation: 2, Legal: 1, Aerospace: 1 },
  },

  'CVE-2021-21972': {
    name: 'VMware vCenter RCE',
    actors: [
      { name: 'UNC2447', aliases: [], origin: 'Unknown', motivation: 'Financial (Ransomware)', first_seen: '2021-02' },
      { name: 'Various APTs', aliases: [], origin: 'Multiple', motivation: 'Espionage', first_seen: '2021-02' },
    ],
    incidents: [
      { name: 'Mass scanning post-disclosure', date: '2021-02', type: 'Mass Exploitation', impact: 'RCE on exposed vCenter instances' },
    ],
    sectors: { Government: 4, Defense: 3, Finance: 4, Healthcare: 3, Energy: 3, Technology: 5, Telecom: 3, Education: 2, Manufacturing: 2, Retail: 1, Media: 1, Transportation: 1, Legal: 1, Aerospace: 2 },
  },

  'CVE-2020-0688': {
    name: 'Exchange Validation Key RCE',
    actors: [
      { name: 'APT groups (multiple)', aliases: [], origin: 'Multiple', motivation: 'Espionage', first_seen: '2020-02' },
    ],
    incidents: [
      { name: 'NSA advisory on active exploitation', date: '2020-03', type: 'Espionage Campaign', impact: 'Authenticated RCE on Exchange servers' },
    ],
    sectors: { Government: 4, Defense: 3, Finance: 3, Healthcare: 2, Energy: 2, Technology: 4, Telecom: 2, Education: 2, Manufacturing: 1, Retail: 1, Media: 1, Transportation: 1, Legal: 2, Aerospace: 1 },
  },
};

/**
 * Look up threat intelligence for a given CVE ID
 * @param {string} cveId - CVE identifier (e.g. CVE-2021-44228)
 * @returns {object|null} Threat intel data or null if no data available
 */
function lookupThreatIntel(cveId) {
  const id = cveId.toUpperCase().trim();
  const entry = CVE_THREAT_DB[id];
  if (!entry) return null;

  // Compute sector heatmap data
  const sectorHeatmap = SECTORS.map(sector => ({
    sector,
    level: entry.sectors[sector] || 0,
  }));

  // Count unique origins for origin distribution
  const origins = {};
  entry.actors.forEach(a => {
    const origin = a.origin.replace(/\s*\(.*\)/, ''); // Strip parenthetical
    origins[origin] = (origins[origin] || 0) + 1;
  });

  return {
    vulnName: entry.name,
    actors: entry.actors,
    incidents: entry.incidents,
    sectorHeatmap,
    actorCount: entry.actors.length,
    incidentCount: entry.incidents.length,
    origins: Object.entries(origins).map(([country, count]) => ({ country, count })),
    maxHeat: Math.max(...sectorHeatmap.map(s => s.level)),
  };
}

module.exports = { lookupThreatIntel, SECTORS };
