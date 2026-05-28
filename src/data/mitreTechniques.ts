export type MitreTactic =
  | 'Reconnaissance'
  | 'Initial Access'
  | 'Execution'
  | 'Persistence'
  | 'Defense Evasion'
  | 'Credential Access'
  | 'Discovery'
  | 'Lateral Movement'
  | 'Collection'
  | 'Command and Control'
  | 'Exfiltration'
  | 'Impact'

export interface MitreTechnique {
  id: string
  name: string
  tactic: MitreTactic
}

export const MITRE_TECHNIQUES: Record<string, MitreTechnique> = {
  'T1595':     { id: 'T1595',     name: 'Active Scanning',                    tactic: 'Reconnaissance' },
  'T1595.001': { id: 'T1595.001', name: 'Scanning IP Blocks',                 tactic: 'Reconnaissance' },
  'T1595.002': { id: 'T1595.002', name: 'Vulnerability Scanning',             tactic: 'Reconnaissance' },
  'T1590':     { id: 'T1590',     name: 'Gather Victim Network Information',   tactic: 'Reconnaissance' },
  'T1190':     { id: 'T1190',     name: 'Exploit Public-Facing Application',   tactic: 'Initial Access' },
  'T1133':     { id: 'T1133',     name: 'External Remote Services',            tactic: 'Initial Access' },
  'T1566':     { id: 'T1566',     name: 'Phishing',                            tactic: 'Initial Access' },
  'T1566.001': { id: 'T1566.001', name: 'Spearphishing Attachment',            tactic: 'Initial Access' },
  'T1566.002': { id: 'T1566.002', name: 'Spearphishing Link',                  tactic: 'Initial Access' },
  'T1059':     { id: 'T1059',     name: 'Command and Scripting Interpreter',   tactic: 'Execution' },
  'T1059.001': { id: 'T1059.001', name: 'PowerShell',                          tactic: 'Execution' },
  'T1059.003': { id: 'T1059.003', name: 'Windows Command Shell',               tactic: 'Execution' },
  'T1053':     { id: 'T1053',     name: 'Scheduled Task / Job',                tactic: 'Persistence' },
  'T1078':     { id: 'T1078',     name: 'Valid Accounts',                      tactic: 'Defense Evasion' },
  'T1055':     { id: 'T1055',     name: 'Process Injection',                   tactic: 'Defense Evasion' },
  'T1027':     { id: 'T1027',     name: 'Obfuscated Files or Information',     tactic: 'Defense Evasion' },
  'T1562':     { id: 'T1562',     name: 'Impair Defenses',                     tactic: 'Defense Evasion' },
  'T1003':     { id: 'T1003',     name: 'OS Credential Dumping',               tactic: 'Credential Access' },
  'T1056':     { id: 'T1056',     name: 'Input Capture',                       tactic: 'Credential Access' },
  'T1110':     { id: 'T1110',     name: 'Brute Force',                         tactic: 'Credential Access' },
  'T1082':     { id: 'T1082',     name: 'System Information Discovery',        tactic: 'Discovery' },
  'T1046':     { id: 'T1046',     name: 'Network Service Discovery',           tactic: 'Discovery' },
  'T1018':     { id: 'T1018',     name: 'Remote System Discovery',             tactic: 'Discovery' },
  'T1021':     { id: 'T1021',     name: 'Remote Services',                     tactic: 'Lateral Movement' },
  'T1021.001': { id: 'T1021.001', name: 'Remote Desktop Protocol',             tactic: 'Lateral Movement' },
  'T1021.002': { id: 'T1021.002', name: 'SMB / Windows Admin Shares',          tactic: 'Lateral Movement' },
  'T1113':     { id: 'T1113',     name: 'Screen Capture',                      tactic: 'Collection' },
  'T1071':     { id: 'T1071',     name: 'Application Layer Protocol',          tactic: 'Command and Control' },
  'T1071.001': { id: 'T1071.001', name: 'Web Protocols',                       tactic: 'Command and Control' },
  'T1071.004': { id: 'T1071.004', name: 'DNS',                                 tactic: 'Command and Control' },
  'T1105':     { id: 'T1105',     name: 'Ingress Tool Transfer',               tactic: 'Command and Control' },
  'T1572':     { id: 'T1572',     name: 'Protocol Tunneling',                  tactic: 'Command and Control' },
  'T1041':     { id: 'T1041',     name: 'Exfiltration Over C2 Channel',        tactic: 'Exfiltration' },
  'T1486':     { id: 'T1486',     name: 'Data Encrypted for Impact',           tactic: 'Impact' },
  'T1498':     { id: 'T1498',     name: 'Network Denial of Service',           tactic: 'Impact' },
  'T1489':     { id: 'T1489',     name: 'Service Stop',                        tactic: 'Impact' },
}

export const TACTIC_ORDER: MitreTactic[] = [
  'Reconnaissance',
  'Initial Access',
  'Execution',
  'Persistence',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
]
