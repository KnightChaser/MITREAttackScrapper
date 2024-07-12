# MITREAttackScrapper/cti/campaigns.py

import httpx
from bs4 import BeautifulSoup, Tag
from typing import List, Dict, Any, Union
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from superclass import MITREAttackInformation
from utils.mitre_id_validator import validate_mitre_campaign_id
from utils.scrapping_helper import get_text_after_span

class MITREAttackCampaign(MITREAttackInformation):
    """
    A class to represent the MITRE ATT&CK campaign.
    """

    @staticmethod
    def get_list() -> List[Dict[str, Any]]:
        """
        Get the list of MITRE ATT&CK campaigns.

        :return: The list of MITRE ATT&CK campaigns.
        :rtype: List[Dict[str, Any]]
        :raises RuntimeError: If the data fetch from the MITRE ATT&CK website fails.

        Example
        -------
        The structure of the returned data is as follows:

        .. code-block:: python

            [
                {
                    "id": "C0001",
                    "name": "Campagin 1",
                    "description": "Description of Campaign 1",
                    "url": "https://attack.mitre.org/campaigns/C0001/",
                },
                ...
            ]
        
        """

        target_url = "https://attack.mitre.org/campaigns/"
        response = httpx.get(target_url)
        if response.status_code != 200:
            raise RuntimeError("Failed to fetch data from MITRE ATT&CK website.")
        campagin_list_data = []

        # Extract the <table> element containing the campagin information
        soup = BeautifulSoup(response.text, "html.parser")
        table = soup.find("table")
        rows = table.find_all("tr")
        for row in rows:
            cells = row.find_all("td")
            if len(cells) == 3:
                campagin_id = cells[0].text.strip()
                campagin_name = cells[1].text.strip()
                campagin_description = cells[2].text.strip()
                campagin_list_data.append({
                    "id": campagin_id,
                    "name": campagin_name,
                    "description": campagin_description,
                    "url": f"https://attack.mitre.org/campaigns/{campagin_id}/",
                })

        return campagin_list_data
    
    @staticmethod
    @validate_mitre_campaign_id
    def get(campagin_id: str) -> Dict[str, Any]:
        """
        Get the details of a specific MITRE ATT&CK campaign.

        :param campagin_id: The MITRE ATT&CK campaign ID.
        :type campagin_id: str
        :return: The details of the MITRE ATT&CK campaign.
        :rtype: Dict[str, Any]
        :raises ValueError: If the provided campaign ID is invalid.
        :raises RuntimeError: If the data fetch from the MITRE ATT&CK website fails.

        Example
        -------
        The structure of the returned data is as follows:

        .. code-block:: python

            {
                "id": "C0001",
                "name": "Campagin 1",
                "first_seen": "YYYY-mm",
                "last_seen": "YYYY-mm",
                "version": "1.0",
                "created": "YYYY-mm-dd",
                "last_modified": "YYYY-mm-dd",
                "description": "Description of Campaign 1",
                "url": "https://attack.mitre.org/campaigns/C0001/",
                "groups": [
                    {
                        "id": "G0001",
                        "name": "Group 1",
                        "description": "Description of Group 1",
                        "url": "https://attack.mitre.org/groups/G0001/",
                    }
                ],
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
                "software": [
                    {
                        "id": "S0001",
                        "name": "Software 1",
                        "description": "Description of Software 1",
                        "url": "https://attack.mitre.org/software/S0001/",
                    }
                ],
                "references": {
                    1: {
                        "text": "Reference 1 Text",
                        "url": "https://example1.com"
                    },
                    2: {
                        "text": "Reference 2 Text",
                        "url": "https://example2.com"
                    },
                    # ... more references
                }
            }
        """

        target_url = f"https://attack.mitre.org/campaigns/{campagin_id}/"
        response = httpx.get(target_url)
        if response.status_code != 200:
            raise RuntimeError("Failed to fetch data from MITRE ATT&CK website.")
        
        soup = BeautifulSoup(response.text, "html.parser")
        campagin_data = {
            "id": campagin_id,
            "name": None,
            "first_seen": None,
            "last_seen": None,
            "version": None,
            "created": None,
            "last_modified": None,
            "description": None,
            "url": target_url,
            "groups": [],
            "techniques_used": [],
            "software": [],
            "references": {}
        }

        # Extract the campagin name
        campagin_data["name"] = soup.find("h1").text.strip()

        # Extract the campagin details by getting card-body
        card_body: Union[Tag, None] = soup.select_one("div.card > div.card-body")
        campagin_data["first_seen"] = soup.find("span", string=lambda text: text and text.strip().lower().startswith("first seen")).find_next("span").text.split('[')[0].strip() \
                                                if soup.find("span", string=lambda text: text and text.strip().lower().startswith("first seen")) else None
        campagin_data["first_seen"] = datetime.strptime(campagin_data["first_seen"], "%B %Y").strftime("%Y-%m")
        campagin_data["last_seen"] = soup.find("span", string=lambda text: text and text.strip().lower().startswith("last seen")).find_next("span").text.split('[')[0].strip() \
                                                if soup.find("span", string=lambda text: text and text.strip().lower().startswith("last seen")) else None
        campagin_data["last_seen"] = datetime.strptime(campagin_data["last_seen"], "%B %Y").strftime("%Y-%m")
        campagin_data["version"] = get_text_after_span(card_body, "Version").split(':')[1].strip()
        campagin_data["created"] = get_text_after_span(card_body, "Created")
        campagin_data["created"] = datetime.strptime(campagin_data["created"], "%d %B %Y").strftime("%Y-%m-%d")
        campagin_data["last_modified"] = get_text_after_span(card_body, "Last Modified")
        campagin_data["last_modified"] = datetime.strptime(campagin_data["last_modified"], "%d %B %Y").strftime("%Y-%m-%d")

        # Extract the campagin description
        description_tag: Union[Tag, None] = card_body.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(2) > div.col-md-8 > div > p")
        campagin_data["description"] = description_tag.text.strip() if description_tag else None

        # Extract the groups associated with the campaign
        associated_groups = []
        groups_table: Union[Tag, None] = soup.find("h2", string="Groups").find_next("table") if soup.find("h2", string="Groups") else None
        if groups_table:
            for row in groups_table.find("tbody").find_all("tr"):
                cells = row.find_all("td")
                if len(cells) == 3:
                    group_id = cells[0].find("a").get_text(strip=True)
                    group_name = cells[1].find("a").get_text(strip=True)
                    description = cells[2].get_text(strip=True)

                    associated_groups.append({
                        "id": group_id,
                        "name": group_name,
                        "description": description,
                        "url": f"https://attack.mitre.org/groups/{group_id}/"
                    })
        campagin_data["groups"] = associated_groups

        # Extract the techniques used
        techniques_used = []
        techniques_table: Union[Tag, None] = soup.find("h2", string="Techniques Used").find_next("table") if soup.find("h2", string="Techniques Used") else None
        if techniques_table:
            latest_domain = None
            latest_main_technique_id = None
            for row in techniques_table.find("tbody").find_all("tr"):
                cells = row.find_all("td")
                if len(cells) == 4:
                    # In case of main-techniques, the domain is repeated
                    domain = cells[0].get_text(strip=True) if cells[0].get_text(strip=True) else latest_domain
                    latest_domain = domain

                    main_technique_id = cells[1].find("a").get_text(strip=True) if cells[1].find("a") else latest_main_technique_id
                    latest_main_technique_id = main_technique_id

                    main_technique_name = cells[2].find("a").get_text(strip=True)
                    use = cells[3].get_text(" ", strip=True)

                    techniques_used.append({
                        "domain": domain,
                        "main_technique_id": main_technique_id,
                        "main_technique_name": main_technique_name,
                        "main_technique_url": f"https://attack.mitre.org/techniques/{main_technique_id}/",
                        "sub_technique_id": None,
                        "sub_technique_name": None,
                        "sub_technique_url": None,
                        "use": use
                    })

                elif len(cells) == 5:
                    # In case of sub-techniques, the main technique ID is repeated
                    domain = cells[0].get_text(strip=True) if cells[0].get_text(strip=True) else latest_domain
                    latest_domain = domain

                    main_technique_id = cells[1].find("a").get_text(strip=True) if cells[1].find("a") else latest_main_technique_id
                    latest_main_technique_id = main_technique_id
                    sub_technique_id = cells[2].find("a").get_text(strip=True) if cells[2].find("a") else None
                    if sub_technique_id:
                        sub_technique_id = sub_technique_id.replace('.', '')
                        sub_technique_full_id = f"{main_technique_id}.{sub_technique_id}"
                        sub_technique_url = f"https://attack.mitre.org/techniques/{main_technique_id}/{sub_technique_id}/"
                    else:
                        sub_technique_id = None
                        sub_technique_url = None

                    main_technique_name = cells[3].find("a").get_text(strip=True)
                    sub_technique_name = cells[3].find_all("a")[1].get_text(strip=True) if len(cells[3].find_all("a")) > 1 else None
                    use = cells[4].get_text(" ", strip=True)

                    techniques_used.append({
                        "domain": domain,
                        "main_technique_id": main_technique_id,
                        "main_technique_name": main_technique_name,
                        "main_technique_url": f"https://attack.mitre.org/techniques/{main_technique_id}/",
                        "sub_technique_id": sub_technique_full_id,
                        "sub_technique_name": sub_technique_name,
                        "sub_technique_url": sub_technique_url,
                        "use": use
                    })

        campagin_data["techniques_used"] = techniques_used

        # Extract the software used by the campaign
        software = []
        software_table: Union[Tag, None] = soup.find("h2", string="Software").find_next("table") if soup.find("h2", string="Software") else None
        if software_table:
            for row in software_table.find_all("tr"):
                cells: List[Tag] = row.find_all("td")
                if len(cells) == 3:
                    software_id = cells[0].find("a").get_text(strip=True)
                    software_name = cells[1].find("a").get_text(strip=True)
                    description = cells[2].get_text(strip=True)

                    software.append({
                        "id": software_id,
                        "name": software_name,
                        "description": description,
                        "url": f"https://attack.mitre.org/software/{software_id}/"
                    })
        campagin_data["software"] = software

        # Extract references
        references_div: Union[Tag, None] = soup.find("h2", string="References").find_next("div") if soup.find("h2", string="References") else None
        reference_number: int = 1
        if references_div:
            for li in references_div.find_all("li"):
                a_tag = li.find("a")
                if a_tag:
                    reference_text = li.get_text(" ", strip=True)
                    reference_href = a_tag["href"]
                    # Add the reference to the references dictionary; the key is the reference number
                    campagin_data["references"][reference_number] = {
                        "text": reference_text,
                        "url": reference_href
                    }
                    reference_number += 1

        return campagin_data