export interface ThreatActor {
  id: string
  name: string
  aliases: string[]
  suspectedOrigin: string
  motivation: 'financial' | 'espionage' | 'disruption' | 'hacktivism'
  malware: string[]
  ttps: string[]
  description: string
  firstSeen: string
}

export const THREAT_ACTOR_DB: ThreatActor[] = [
  {
    id: 'wizard-spider',
    name: 'Wizard Spider',
    aliases: ['UNC1878', 'Gold Blackburn', 'DEV-0193'],
    suspectedOrigin: 'Russia',
    motivation: 'financial',
    malware: ['TrickBot', 'BazarLoader'],
    ttps: ['T1059', 'T1486', 'T1021', 'T1055', 'T1071'],
    description:
      'Russia-based eCrime group responsible for TrickBot and the Conti ransomware-as-a-service operation. Major initial access broker partnering with multiple ransomware affiliates.',
    firstSeen: '2016',
  },
  {
    id: 'ta542',
    name: 'TA542',
    aliases: ['Mummy Spider', 'Gold Crestwood'],
    suspectedOrigin: 'Eastern Europe',
    motivation: 'financial',
    malware: ['Emotet'],
    ttps: ['T1566', 'T1071', 'T1055', 'T1059'],
    description:
      'Operates the Emotet malware-as-a-service platform — one of the most disruptive botnet infrastructures ever observed. Rents access to Ryuk, Conti, and other ransomware groups.',
    firstSeen: '2014',
  },
  {
    id: 'evil-corp',
    name: 'Evil Corp',
    aliases: ['Indrik Spider', 'Gold Drake'],
    suspectedOrigin: 'Russia',
    motivation: 'financial',
    malware: ['Dridex'],
    ttps: ['T1566', 'T1059', 'T1021', 'T1486', 'T1071'],
    description:
      'OFAC-sanctioned Russian cybercriminal syndicate behind the Dridex banking trojan and ransomware families including WastedLocker, Hades, and Phoenix Locker.',
    firstSeen: '2007',
  },
  {
    id: 'ta570',
    name: 'TA570',
    aliases: ['Gold Lagoon'],
    suspectedOrigin: 'Eastern Europe',
    motivation: 'financial',
    malware: ['QakBot'],
    ttps: ['T1566', 'T1071', 'T1059', 'T1055'],
    description:
      'Primary QakBot (QBot) operator and prolific initial access broker. Frequently partners with Black Basta, Conti, and other ransomware groups for post-exploitation.',
    firstSeen: '2019',
  },
  {
    id: 'ta551',
    name: 'TA551',
    aliases: ['Hive0106', 'Shathak'],
    suspectedOrigin: 'Unknown',
    motivation: 'financial',
    malware: ['IcedID'],
    ttps: ['T1566', 'T1071', 'T1055'],
    description:
      'High-volume initial access broker distributing IcedID (BokBot) banking trojan via reply-chain email hijacking campaigns. Provides consistent access to ransomware operators.',
    firstSeen: '2018',
  },
  {
    id: 'apt28',
    name: 'APT28',
    aliases: ['Fancy Bear', 'Sofacy', 'Strontium', 'Forest Blizzard', 'Pawn Storm'],
    suspectedOrigin: 'Russia (GRU Unit 26165)',
    motivation: 'espionage',
    malware: ['Cobalt Strike'],
    ttps: ['T1566', 'T1071', 'T1059', 'T1078', 'T1055'],
    description:
      'GRU-affiliated Russian APT conducting cyberespionage against NATO governments, political entities, and critical infrastructure. Responsible for the 2016 DNC breach and multiple election interference campaigns.',
    firstSeen: '2004',
  },
  {
    id: 'fin7',
    name: 'FIN7',
    aliases: ['Carbanak Group', 'Gold Niagara', 'Sangria Tempest', 'Carbon Spider'],
    suspectedOrigin: 'Russia / Ukraine',
    motivation: 'financial',
    malware: ['Cobalt Strike', 'Remcos'],
    ttps: ['T1566', 'T1059', 'T1021', 'T1486', 'T1055'],
    description:
      'Sophisticated cybercriminal group targeting retail, hospitality, and financial sectors. Operates or affiliates with Darkside and BlackCat ransomware programs. Estimated to have stolen over $1B.',
    firstSeen: '2013',
  },
  {
    id: 'lazarus',
    name: 'Lazarus Group',
    aliases: ['APT38', 'Hidden Cobra', 'Zinc', 'Nickel Academy'],
    suspectedOrigin: 'North Korea (RGB)',
    motivation: 'financial',
    malware: ['AsyncRAT', 'NanoCore'],
    ttps: ['T1566', 'T1059', 'T1082', 'T1055', 'T1071'],
    description:
      'North Korean state-sponsored threat actor conducting cryptocurrency theft, ransomware (WannaCry), and espionage to fund the DPRK regime. Responsible for billions in crypto heists.',
    firstSeen: '2009',
  },
  {
    id: 'ta505',
    name: 'TA505',
    aliases: ['Hive0065', 'Spandex Tempest'],
    suspectedOrigin: 'Russia',
    motivation: 'financial',
    malware: ['AsyncRAT', 'Remcos'],
    ttps: ['T1566', 'T1059', 'T1021', 'T1071'],
    description:
      'Prolific financially-motivated actor known for massive malspam campaigns distributing RATs and banking trojans. Linked to the Clop ransomware group and large-scale MOVEit exploitation.',
    firstSeen: '2014',
  },
  {
    id: 'ta2719',
    name: 'TA2719',
    aliases: [],
    suspectedOrigin: 'Unknown',
    motivation: 'financial',
    malware: ['AgentTesla', 'FormBook', 'NanoCore'],
    ttps: ['T1566', 'T1056', 'T1041', 'T1071'],
    description:
      'Commodity malware distributor specialising in credential harvesting via AgentTesla and FormBook stealers. Primarily targets SMEs through phishing with low operational sophistication.',
    firstSeen: '2018',
  },
  {
    id: 'sidewinder',
    name: 'SideWinder',
    aliases: ['APT-C-17', 'Rattlesnake', 'T-APT-04'],
    suspectedOrigin: 'India (suspected)',
    motivation: 'espionage',
    malware: ['AgentTesla', 'FormBook'],
    ttps: ['T1566', 'T1059', 'T1082', 'T1071'],
    description:
      'Suspected Indian APT group conducting espionage campaigns against Pakistani, Chinese, and South Asian government targets using spear-phishing and commodity remote access tools.',
    firstSeen: '2012',
  },
]

export function getActorsForMalware(family: string): ThreatActor[] {
  return THREAT_ACTOR_DB.filter(a => a.malware.includes(family))
}
