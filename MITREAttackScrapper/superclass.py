# MITREAttackScrapper/superclass.py
from typing import List, Dict, Any
from abc import abstractmethod

class MITREAttackInformation():
    @abstractmethod
    def get_list() -> List[Dict[str, Any]]:
        """
        Get the list of all MITRE ATT&CK data.
        """
        pass

    @abstractmethod
    def get(id: str) -> Dict[str, Any]:
        """
        Get the details of a specific MITRE ATT&CK data.
        """
        pass
        