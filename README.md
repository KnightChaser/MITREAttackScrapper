# MITREAttackScrapper
### A simple and easy data scrapper for **MITRE ATT&CK** information for threat intelligence and knowledge bases, written in Python3.
> Un scrapper de datos simple y fácil para la información de **MITRE ATT&CK** para inteligencia de amenazas y bases de conocimiento, escrito en Python3.

```py
# Need to MITRE ATT&CK data? How about using my package?
from MITREAttackScrapper.techniques.enterprise import MITREAttackEnterpriseTechniques

if __name__ == '__main__':
    detail = MITREAttackEnterpriseTechniques.get("T1548.001")
    print(f"Technique: {detail['name']}")
    print(f"Platforms affected by this technique: {detail['platforms']}")
    print(f"Number of mitigation suggested: {len(detail['mitigations'])}")

    # Technique: Abuse Elevation Control Mechanism
    # Platforms affected by this technique: ['Azure AD', 'Google Workspace', 'IaaS', 'Linux', 'Office 365', 'Windows', 'macOS']
    # Number of mitigation suggested: 1
```

### Note: Currently under development, not stable!!!

## How to use?
Refer to the **[documentation](https://knightchaser.github.io/MITREAttackScrapper/)**! >_<

## Coverage
- **TECHNIQUES**
  - [x] MITRE ATT&CK Enterprise Techniques
  - [ ] MITRE ATT&CK Mobile Techniques
  - [ ] MITRE ATT&CK ICS Techniques
- **TACTICS**
  - [x] MITRE ATT&CK Enterprise Tactics
  - [ ] MITRE ATT&CK Mobile Tactics
  - [ ] MITRE ATT&CK ICS Tactics
- **CTI**
  - [x] MITRE ATT&CK CTI Groups
  - [x] MITRE ATT&CK CTI Software
  - [ ] MITRE ATT&CK CTI Campaigns
- **Defenses/Mitigations**
  - [x] MITRE ATT&CK Enterprise Mitigations(Defenses)
  - [ ] MITRE ATT&CK Mobile Mitigations(Defenses)
  - [ ] MITRE ATT&CK ICS Mitigations(Defenses)
- **ATT&CK MATRICES**
  - [ ] MITRE ATT&CK Enterprise Matrices
  - [ ] MITRE ATT&CK Mobile Matrices
  - [ ] MITRE ATT&CK ICS Matrices