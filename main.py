# main.py
from pprint import pprint
from utils.enterprise_techniques import MITREAttackEnterpriseTechniques

pprint(MITREAttackEnterpriseTechniques.get_attack_list())
pprint("=====================================================")
pprint(MITREAttackEnterpriseTechniques.get_parent_technique(technique_id="T1548"))
pprint("=====================================================")
pprint(MITREAttackEnterpriseTechniques.get_child_technique(parent_technique_id="T1548", child_technique_id="001"))
pprint("=====================================================")