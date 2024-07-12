# MITREAttackScrapper/cti/software.py

import httpx
from bs4 import BeautifulSoup, Tag
from typing import List, Dict, Any, Union
from datetime import datetime

from ..superclass import MITREAttackInformation
from ..utils.mitre_id_validator import validate_mitre_software_id
from ..utils.scrapping_helper import get_text_after_span

class MITREAttackCTISoftware(MITREAttackInformation):
    """
    A class containing methods to scrap MITRE ATT&CK Softwares.
    """

    @staticmethod
    def get_list() -> List[Dict[str, Any]]:
        """
        Get the list of all MITRE ATT&CK Softwares.

        :return: A list of dictionaries containing the software's name, id, and description.
        :rtype: List[Dict[str, Any]]
        :raises RuntimeError: If the data fetch from the MITRE ATT&CK website fails.

        Example
        -------
        The return value will be in the following format:

        .. code-block:: python

            [
                {
                    "id": "S0001",
                    "name": "APT1",
                    "associated_software": [
                        "software1",
                        "software2"
                    ],
                    "description": "APT1 is a Chinese threat group that has been attributed to China's People's Liberation Army (PLA) Third Department 12th Bureau."
                },
                # ... more software
            ]
        """

        target_url = "https://attack.mitre.org/software/"
        response = httpx.get(target_url)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch data from {target_url}")
        data = []

        # Extract the <table> element containing the groups
        soup = BeautifulSoup(response.text, "html.parser")
        table = soup.find("table")
        rows = table.find_all("tr")
        for row in rows:
            cells = row.find_all("td")
            if len(cells) == 4:
                software_id: str = cells[0].text.strip()
                software_name: str = cells[1].text.strip()
                software_associated_software: Union[List[str], None] = cells[2].text.strip().split(',') if cells[2].text.strip() else None
                software_description: str = cells[3].text.strip()
                data.append({
                    "id": software_id,
                    "name": software_name,
                    "associated_software": software_associated_software,
                    "description": software_description
                })
        
        return data
    
    @staticmethod
    @validate_mitre_software_id
    def get(software_id: str) -> Dict[str, Any]:
        """
        Get the information of a specific MITRE ATT&CK Software.

        :param software_id: The ID of the software.
        :type software_id: str
        :return: A dictionary containing information about the specific MITRE ATT&CK Software.
        :rtype: Dict[str, Any]
        :raises ValueError: If the provided software ID format is invalid.
        :raises RuntimeError: If the data fetch from the MITRE ATT&CK website fails.
        
        Example
        -------
        The return value will be in the following format:

        .. code-block:: python

            {
                "id": "S0001",
                "name": "software 1",
                "type": "malware",
                "platforms": [
                    "platform 1",
                    "platform 2",
                    ...
                ],
                "version": "version 1",
                "created": "20XX-XX-XX",
                "last_modified": "20XX-XX-XX",
                "description": "description of the software",
                "techniques_used": [
                    {
                        "domain": "Enterprise",
                        "main_technique_id": "T0001",
                        "main_technique_name": "Main Technique Name",
                        "main_technique_url": "https://attack.mitre.org/techniques/T0001/",
                        "sub_technique_id": "T0001.001",
                        "sub_technique_name": "Sub-Technique Name",
                        "sub_technique_url": "https://attack.mitre.org/techniques/T0001/001/",
                        "use": "Technique Use Description"
                    },
                    # ... more techniques
                ],
                "groups_that_use_this_software": [
                    {
                        "id": "GXXXX",
                        "name": "group 1",
                        "reference": "https://attack.mitre.org/groups/GXXXX/"    
                    }
                ],
                "references": {
                    1: {
                        "text": "Reference 1",
                        "url": "https://example.com"
                    },
                    # ... more references
                }
            }
        """

        target_url = f"https://attack.mitre.org/software/{software_id}/"
        response = httpx.get(target_url)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch data from {target_url}")

        soup = BeautifulSoup(response.text, "html.parser")
        software_data = {
            "id": software_id,
            "name": None,
            "type": None,
            "platforms": [],
            "version": None,
            "created": None,
            "last_modified": None,
            "description": None,
            "techniques_used": [],
            "groups_that_use_this_software": [],
            "references": {}
        }

        # Extract the group name
        software_data["name"] = soup.find("h1").text.strip()

        # Extract the card body
        card_body: Union[Tag, None] = soup.select_one("div.card > div.card-body")
        software_data["type"] = get_text_after_span(card_body, "Type").replace(':', '').strip()
        software_data["platforms"] = [text.replace(':', '').strip() for text in get_text_after_span(card_body, "Platforms").split(',')]
        software_data["version"] = get_text_after_span(card_body, "Version").strip().split(' ')[1]

        created_text = get_text_after_span(card_body, "Created")
        last_modified_text = get_text_after_span(card_body, "Last Modified")
        software_data["created"]  = datetime.strptime(created_text, "%d %B %Y").strftime("%Y-%m-%d")
        software_data["last_modified"] = datetime.strptime(last_modified_text, "%d %B %Y").strftime("%Y-%m-%d")

        # Extract the description
        description_tag: Union[Tag, None] = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(2) > div.col-md-8 > div > p")
        software_data["description"] = description_tag.text.strip() if description_tag else None

        # Extract the techniques used
        techniques_used = []
        techniques_used_table = soup.find("table", class_="table techniques-used background table-bordered")
        if techniques_used_table:
            latest_technique_domain = None
            latest_main_technique_id = None
            for row in techniques_used_table.find_all("tr")[1:]:
                cells = row.find_all("td")
                if len(cells) == 4:
                    # Extract the main technique information
                    technique_domain = cells[0].text.strip() if cells[0].text.strip() else latest_technique_domain
                    latest_technique_domain = technique_domain

                    main_technique_id = cells[1].text.strip() if cells[1].text.strip() else latest_main_technique_id
                    latest_main_technique_id = main_technique_id

                    main_technique_name = cells[2].text.strip()
                    main_technique_url = f"https://attack.mitre.org/techniques/{main_technique_id}/"

                    main_technique_use = cells[3].text.strip()
                    techniques_used.append({
                        "domain": technique_domain,
                        "main_technique_id": main_technique_id,
                        "main_technique_name": main_technique_name,
                        "main_technique_url": main_technique_url,
                        "sub_technique_id": None,
                        "sub_technique_name": None,
                        "sub_technique_url": None,
                        "use": main_technique_use
                    })

                elif len(cells) == 5:
                    # Extract the sub-technique information
                    technique_domain = cells[0].text.strip() if cells[0].text.strip() else latest_technique_domain
                    latest_technique_domain = technique_domain

                    main_technique_id = cells[1].text.strip() if cells[1].text.strip() else latest_main_technique_id
                    latest_main_technique_id = main_technique_id
                    main_technique_url = f"https://attack.mitre.org/techniques/{main_technique_id}/"

                    sub_technique_id = cells[2].text.strip().replace(".", "")
                    sub_technique_url = f"https://attack.mitre.org/techniques/{main_technique_id}/{sub_technique_id}/"
                    full_sub_technique_id = f"{main_technique_id}.{sub_technique_id}" if sub_technique_id else None

                    technique_name: str = cells[3].text.strip()
                    main_technique_name = technique_name.split(":")[0].strip()
                    sub_technique_name = technique_name.split(":")[1].strip() if ":" in technique_name else None

                    technique_use = cells[4].text.strip()

                    techniques_used.append({
                        "domain": technique_domain,
                        "main_technique_id": main_technique_id,
                        "main_technique_name": main_technique_name,
                        "main_technique_url": main_technique_url,
                        "sub_technique_id": full_sub_technique_id,
                        "sub_technique_name": sub_technique_name,
                        "sub_technique_url": sub_technique_url,
                        "use": technique_use
                    })
        software_data["techniques_used"] = techniques_used

        # Extract the groups that use this software
        groups_that_use_this_software = []
        software_table = soup.find("table", class_="table table-bordered table-alternate mt-2")
        if software_table:
            for row in software_table.find_all("tr"):
                cells: List[Tag] = row.find_all("td")
                if len(cells) == 3:
                    group_id = cells[0].text.strip()
                    group_name = cells[1].text.strip()
                    group_reference = cells[2].find("a")["href"] if cells[2].find("a") else None
                    groups_that_use_this_software.append({
                        "id": group_id,
                        "name": group_name,
                        "reference": group_reference
                    })
        software_data["groups_that_use_this_software"] = groups_that_use_this_software

        # Extract the references
        references_div: Union[Tag, None] = soup.find("h2", string="References").find_next("div") if soup.find("h2", string="References") else None
        reference_number: int = 1
        if references_div:
            for li in references_div.find_all("li"):
                a_tag = li.find("a")
                if a_tag:
                    reference_text = li.get_text(" ", strip=True)
                    reference_href = a_tag["href"]
                    # Add the reference to the references dictionary; the key is the reference number
                    software_data["references"][reference_number] = {
                        "text": reference_text,
                        "url": reference_href
                    }
                    reference_number += 1

        return software_data

    
if __name__ == "__main__":
    from pprint import pprint
    import json

    # Get the list of all MITRE ATT&CK Softwares
    # And then iterate over each software to get the detailed information, for brevity, only get len(json.dumps(detail))
    software_list = MITREAttackCTISoftware.get_list()
    for software in software_list:
        detail = MITREAttackCTISoftware.get(software["id"])
        print(f"Software ID: {software['id']}, Detail Length: {len(json.dumps(detail))}")