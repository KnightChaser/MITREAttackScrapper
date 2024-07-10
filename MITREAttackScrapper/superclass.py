# MITREAttackScrapper/superclass.py
from typing import List, Dict, Any
from abc import abstractmethod

class MITREAttackInformation:
    """
    An abstract base class for MITRE ATT&CK data scraping.

    Methods
    -------
    get_list() -> List[Dict[str, Any]]:
        Abstract method to get the list of all MITRE ATT&CK data.
    
    get(id: str) -> Dict[str, Any]:
        Abstract method to get the details of a specific MITRE ATT&CK data.

    Examples
    --------
    The following example demonstrates how to use the superclass. It prints the list of all MITRE ATT&CK data and the details of the first data.
    Since all the classes using this superclass have the same structure, the same code can be used for all of them.

    .. code-block:: python
    
        from pprint import pprint
        from MITREAttackScrapper.techniques.enterprise import MITREAttackEnterpriseTechniques
        from MITREAttackScrapper.tactics.enterprise import MITREAttackEnterpriseTactics
        from MITREAttackScrapper.mitigations.enterprise import MITREAttackEnterpriseMitigations
        from MITREAttackScrapper.superclass import MITREAttackInformation

        def render(mitre: MITREAttackInformation) -> None:
            data = mitre.get_list()
            target_id = data[0]["id"]
            pprint(mitre.get(target_id))

        if "__main__" == __name__:
            render(MITREAttackEnterpriseTechniques)
            render(MITREAttackEnterpriseTactics)
            render(MITREAttackEnterpriseMitigations)
            print("Done!")
    """

    @abstractmethod
    def get_list() -> List[Dict[str, Any]]:
        """
        Get the list of all MITRE ATT&CK data.

        Returns
        -------
        List[Dict[str, Any]]
            A list of dictionaries containing MITRE ATT&CK data.
        """
        pass

    @abstractmethod
    def get(id: str) -> Dict[str, Any]:
        """
        Get the details of a specific MITRE ATT&CK data.

        Parameters
        ----------
        id : str
            The ID of the specific MITRE ATT&CK data.

        Returns
        -------
        Dict[str, Any]
            A dictionary containing the details of the specified MITRE ATT&CK data.
        """
        pass
