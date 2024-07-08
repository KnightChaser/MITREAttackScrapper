# MITREAttackScrapper
### A simple and easy data scrapper for **MITRE ATT&CK** information for threat intelligence and knowledge bases, written in Python3.
> Un scrapper de datos simple y fácil para la información de **MITRE ATT&CK** para inteligencia de amenazas y bases de conocimiento, escrito en Python3.

### Note: Currently under development


## Usage
- [x] **MITRE ATT&CK Enterprise Techniques** 
  - Import `MITREAttackEnterpriseTechniques` class
  - Use `get_attack_list()` for getting all MITRE ATT&CK Enterprise technique lists(including both parent and child technique entries)
  - Use `get()` for getting a detailed information for a specific MITRE ATT&CK Enterprise technique entry such as `T1548` or `T1548.001`.  (Covering both parent and child technique entries)
```python
from pprint import pprint
from MITREAttackScrapper.enterprise_techniques import MITREAttackEnterpriseTechniques

pprint(MITREAttackEnterpriseTechniques.get_attack_list())
pprint(MITREAttackEnterpriseTechniques.get("T1548"))
pprint(MITREAttackEnterpriseTechniques.get("T1548.001"))
```

- **Future implementations**
  - [ ] MITRE ATT&CK Mobile Techniques
  - [ ] MITRE ATT&CK ICS Techniques
  - [ ] MITRE ATT&CK Enterprise Tactics
  - [ ] MITRE ATT&CK Mobile Tactics
  - [ ] MITRE ATT&CK ICS Tactics
  - [ ] MITRE ATT&CK CTI Groups
  - [ ] MITRE ATT&CK CTI Software
  - [ ] MITRE ATT&CK CTI Campaigns
  - [ ] MITRE ATT&CK Enterprise Mitigations(Defenses)
  - [ ] MITRE ATT&CK Mobile Mitigations(Defenses)
  - [ ] MITRE ATT&CK ICS Mitigations(Defenses)
  - Not sure about implementation
    - [ ] MITRE ATT&CK Enterprise Matrices
    - [ ] MITRE ATT&CK Mobile Matrices
    - [ ] MITRE ATT&CK ICS Matrices