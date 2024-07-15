# MITREAttackScrapper/matrices/enterprise.py

import httpx
import pandas as pd
from bs4 import BeautifulSoup, Tag
from typing import List, Dict, Any, Union

from ..superclass import MITREAttackInformation
from ..techniques.enterprise import MITREAttackEnterpriseTechniques
from ..utils.mitre_id_validator import validate_mitre_technique_id

class MITREAttackEnterpriseMatrix(MITREAttackInformation):
    """
    A class containing methods to parse MITRE ATT&CK Enterprise Matrices.
    """

    @staticmethod
    def get_list() -> Dict[str, Any]:
        """
        Get the list of all MITRE ATT&CK matrices information for Enterprise,
        in the form of a hierarchical tree expressed as a dictionary.

        The Matrix contains information for the following platforms: 
        Windows, macOS, Linux, PRE, Azure AD, Office 365, Google Workspace, SaaS, IaaS, Network, Containers.

        :return: A dictionary containing MITRE ATT&CK matrices data.
        :rtype: Dict[str, Any]
        :raises ValueError: If the `technique_id` is not a valid MITRE ATT&CK ID.
        :raises RuntimeError: If there's a failure in fetching data from the MITRE ATT&CK website.

        Example
        -------

        .. code-block:: python

            {
                "tactic_name": {
                    "id": "TA1234",
                    "url": "https://attack.mitre.org/tactics/TA1234/",
                    "main_technique" : [
                        {
                            "id": "T1234",
                            "name": "Technique Name",
                            "url": "https://attack.mitre.org/techniques/T1234/",
                            "mitre_tactic_uuid4": "daa4daa4-1234-5678-1234-56781234",
                            "mitre_attack_pattern_uuid4": "daa4daa4-1234-5678-1234-56781234",
                            "sub_technique": [
                                {
                                    "id": "T1234.001",
                                    "name": "Sub-Technique Name",
                                    "url": "https://attack.mitre.org/techniques/T1234.001/",
                                    "mitre_tactic_uuid4": "daa4daa4-1234-5678-1234-56781234",
                                    "mitre_attack_pattern_uuid4": "daa4daa4-1234-5678-1234-56781234",
                                },
                                ...
                            ]
                        },
                        ...
                    ]
                }
            }
        """
        target_url = "https://attack.mitre.org/matrices/enterprise/"
        response = httpx.get(target_url)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch data from {target_url}")
        matrix_data = {}

        # Extract the <table> element containing the matrices
        soup = BeautifulSoup(response.text, "html.parser")

        # Extract the encompassing MITRE ATT&CK tactics
        tactics_data_chunk_location: Union[Tag, None] = soup.select_one("#layouts-content > div.matrix-type.side > div > div > div.overflow-x-auto.matrix-scroll-box.pb-3 > table > thead > tr:nth-child(1)")
        if tactics_data_chunk_location:
            for tactic in tactics_data_chunk_location.find_all("td"):
                tactic_name = tactic.text.strip()
                tactic_id = tactic.find("a")['title'].strip()
                tactic_url = f"https://attack.mitre.org/tactics/{tactic_id}/"
                matrix_data[tactic_name] = {
                    "id": tactic_id,
                    "url": tactic_url,
                    "main_technique": []
                }

        # Extract the encompassing MITRE ATT&CK techniques, and sequentially organize them under their respective tactics
        # At the moment when this code was written, there were 14 major tactics in the Enterprise Matrix.
        # - Reconnaisance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact
        main_technique_table: Union[Tag, None] = soup.select_one("#layouts-content > div.matrix-type.side > div > div > div.overflow-x-auto.matrix-scroll-box.pb-3 > table > tbody > tr")
        main_technique_table_list: List[Tag] = main_technique_table.find_all("td", class_="tactic")

        for main_technique_table in main_technique_table_list:
            for main_technique_row in main_technique_table.find_all("tr", class_="technique-row"):
                technique = main_technique_row.find("div", class_="supertechniquecell")
                if not technique:
                    continue
                
                # Parse the main technique
                technique_anchor: str                           = technique.find("a")
                technique_id: str                               = technique_anchor['title'].strip()
                technique_name: str                             = technique_anchor.text.strip().split(u"\xa0")[0]        # Remove the unicode character
                technique_url: str                              = f"https://attack.mitre.org{technique_anchor['href']}"
                main_technique_mitre_tactic_uuid4: str          = technique['id'].split('--')[2].strip()
                main_technique_mitre_attack_pattern_uuid4: str  = technique['id'].split('--')[4].strip()

                # Parse the sub-techniques associated with the main technique if they exist
                sub_techniques = []
                sub_techniques_container = main_technique_row.find("div", class_="subtechniques-container")
                if sub_techniques_container:
                    for sub_technique_div in sub_techniques_container.find_all("div", class_="subtechnique"):
                        sub_technique: str                              = sub_technique_div.find("div", class_="technique-cell")
                        sub_technique_anchor: str                       = sub_technique.find("a")
                        sub_technique_id: str                           = sub_technique_anchor['title'].strip()
                        sub_technique_name: str                         = sub_technique_anchor.text.strip().split(u"\xa0")[0]        # Remove the unicode character
                        sub_technique_url: str                          = f"https://attack.mitre.org{sub_technique_anchor['href']}"
                        sub_technique_mitre_tactic_uuid4: str           = sub_technique['id'].split('--')[2].strip()
                        sub_technique_mitre_attack_pattern_uuid4: str   = sub_technique['id'].split('--')[4].strip()

                        sub_techniques.append({
                            "id": sub_technique_id,
                            "name": sub_technique_name,
                            "url": sub_technique_url,
                            "mitre_tactic_uuid4": sub_technique_mitre_tactic_uuid4,
                            "mitre_attack_pattern_uuid4": sub_technique_mitre_attack_pattern_uuid4
                        })

                # Determine which tactic this technique belongs to
                tactic_index = main_technique_table_list.index(main_technique_table)
                tactic_name = list(matrix_data.keys())[tactic_index]
                matrix_data[tactic_name]["main_technique"].append({
                    "id": technique_id,
                    "name": technique_name,
                    "url": technique_url,
                    "mitre_tactic_uuid4": main_technique_mitre_tactic_uuid4,
                    "mitre_attack_pattern_uuid4": main_technique_mitre_attack_pattern_uuid4,
                    "sub_technique": sub_techniques
                })

        return matrix_data
    
    @staticmethod
    def get_matrix_dataframe() -> pd.DataFrame:
        """
        Get the MITRE ATT&CK Enterprise Matrix data in the form of a pandas DataFrame.
        The columns will be the tactic names, and the rows will be the techniques under each tactic.

        Due to the limitation of the dimension of the DataFrame, the sub-techniques will not be included in the DataFrame.

        Example
        -------
        The generated DataFrame will look like the following:

        .. code-block:: text

            Collection        Command and Control        ...
            T1234 Technique   T1235 Technique            ...
            T1236 Technique   T1237 Technique            ...
            ...               ...                        ...

        Note that the Pandas DataFrame will be rectangular, with the maximum number of techniques under any tactic.
        Thus, the Pandas DataFrame will be padded with `None` values where necessary.

        :return: A pandas DataFrame containing MITRE ATT&CK Enterprise Matrix data.
        :rtype: pd.DataFrame
        """
        matrix_data: Dict[str, Any] = MITREAttackEnterpriseMatrix.get_list()
        matrix_columns: List[str] = list(matrix_data.keys())
        tactics_techniques = {tactic: [] for tactic in matrix_columns}          # Create a dictionary to hold the techniques aligned with tactics

        # Populate the tactics_techniques dictionary with techniques
        for tactic_name in matrix_data:
            for technique in matrix_data[tactic_name]["main_technique"]:
                tactics_techniques[tactic_name].append(technique["name"])

        # Find the maximum number of techniques under any tactic and fill the rest with None to get a rectangular matrix
        max_techniques = max(len(techniques) for techniques in tactics_techniques.values())
        for tactic in tactics_techniques:
            tactics_techniques[tactic] += [None] * (max_techniques - len(tactics_techniques[tactic]))

        matrix_dataframe = pd.DataFrame(tactics_techniques)
        return matrix_dataframe
    
    @staticmethod
    @validate_mitre_technique_id
    def get(technique_id: str) -> Dict[str, Any]:
        """
        Get the details of a specific MITRE ATT&CK technique for Enterprise.
        Since the MITRE ATT&CK Enterprise matrix contains MITRE ATT&CK techniques in hierarchical order,
        it's just the same as getting the details of a technique.

        Refer to the `MITREAttackEnterpriseTechniques.get()` method for more information.

        :param technique_id: The ID of the specific MITRE ATT&CK technique.
        :type technique_id: str
        :return: A dictionary containing the details of the specified MITRE ATT&CK technique.
        :rtype: Dict[str, Any]
        :raises ValueError: If the `technique_id` is not a valid MITRE ATT&CK ID.
        """
        return MITREAttackEnterpriseTechniques.get(technique_id)