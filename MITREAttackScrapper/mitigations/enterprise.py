# MITREAttackScrapper/mitigations/enterprise.py

import httpx
from bs4 import BeautifulSoup, Tag
from typing import List, Dict, Any, Union
from datetime import datetime

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from superclass import MITREAttackInformation
from utils.scrapping_helper import get_text_after_span
from utils.mitre_id_validator import validate_mitre_mitigation_id

class MITREAttackEnterpriseMitigations(MITREAttackInformation):
    """A class containing methods to parse MITRE ATT&CK Enterprise Mitigations."""

    @staticmethod
    def get_list() -> List[Dict[str, Any]]:
        """
        Get the list of all MITRE ATT&CK mitigations for Enterprise.

        :return: A list of dictionaries containing MITRE ATT&CK mitigations data.
        :rtype: List[Dict[str, Any]]
        :raises RuntimeError: If there's a failure in fetching data from the MITRE ATT&CK website.

        :Example:

        .. code-block:: python

            [
                {
                    "id": "M1234",
                    "name": "Mitigation Name",
                    "description": "Mitigation Description",
                    "url": "https://attack.mitre.org/mitigations/M1234/"
                },
                # ... more mitigation entries
            ]
        """
        target_url = "https://attack.mitre.org/mitigations/enterprise/"
        response = httpx.get(target_url)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch data from {target_url}")
        data = []

        # Extract the <table> element containing the mitigations
        soup = BeautifulSoup(response.text, "html.parser")
        table = soup.find("table")
        rows = table.find_all("tr")
        for row in rows:
            cells = row.find_all("td")
            if len(cells) == 3:
                id = cells[0].text.strip()
                name = cells[1].text.strip()
                description = cells[2].text.strip()
                url = f"https://attack.mitre.org{cells[0].find('a')['href']}"
                data.append({
                    "id": id,
                    "name": name,
                    "description": description,
                    "url": url
                })
        
        return data
    
    @staticmethod
    @validate_mitre_mitigation_id
    def get(mitigation_id: str) -> Dict[str, Any]:
        """
        Get the details of a specific MITRE ATT&CK mitigation for Enterprise.

        :param mitigation_id: The ID of the specific MITRE ATT&CK mitigation.
        :type mitigation_id: str
        :return: A dictionary containing the details of the specified MITRE ATT&CK mitigation.
        :rtype: Dict[str, Any]
        :raises ValueError: If the mitigation ID does not exist in the MITRE ATT&CK Enterprise mitigations.
        :raises RuntimeError: If there's a failure in fetching data from the MITRE ATT&CK website.

        :Example:

        .. code-block:: python

            {
                "id": "M1234",
                "name": "Mitigation Name",
                "version": "1.0",
                "created": "2021-01-01",
                "last_modified": "2021-01-01",
                "url": "https://attack.mitre.org/mitigations/M1234/",
                "description": "Mitigation Description",
                "techniques_addressed_by_mitigation": [
                    {
                        "domain": "Enterprise",
                        "id": "T1234",
                        "name": "Technique Name",
                        "use": "Technique Use",
                        "url": "https://attack.mitre.org/techniques/T1234/"
                    }
                ],
                "references": {
                    1: {
                        "text": "Reference 1",
                        "url": "https://example1.com"
                    },
                    2: {
                        "text": "Reference 2",
                        "url": "https://example2.com"
                    }
                }
            }
        """
        target_url = f"https://attack.mitre.org/mitigations/{mitigation_id}/"
        response = httpx.get(target_url)
        if response.status_code != 200:
            if response.status_code == 404:
                raise ValueError(f"The mitigation {mitigation_id} does not exist in the MITRE ATT&CK Enterprise mitigations")
            raise RuntimeError(f"Failed to fetch data from {target_url}")

        soup = BeautifulSoup(response.text, "html.parser")

        # Extract the card body containing basic information
        card_body: Union[Tag, None] = soup.select_one("div.card > div.card-body")
        if not card_body:
            raise RuntimeError(f"Failed to parse the card body for {mitigation_id}")

        # Initialize the result dictionary
        mitigation_data: Dict[str, Any] = {
            "id": mitigation_id,
            "name": "",
            "version": "",
            "created": None,
            "last_modified": None,
            "url": target_url,
            "description": "",
            "techniques_addressed_by_mitigation": [],
            "references": {}
        }

        # Parse basic information
        mitigation_data["name"] = soup.find("h1").get_text(strip=True)
        mitigation_data["version"] = get_text_after_span(card_body, "Version:")
        created_text = get_text_after_span(card_body, "Created:")
        if created_text:
            mitigation_data["created"] = datetime.strptime(created_text, "%d %B %Y").strftime("%Y-%m-%d")
        last_modified_text = get_text_after_span(card_body, "Last Modified:")
        if last_modified_text:
            mitigation_data["last_modified"] = datetime.strptime(last_modified_text, "%d %B %Y").strftime("%Y-%m-%d")

        # Parse description
        description_div: Union[Tag, None] = soup.select_one("div.description-body")
        if description_div:
            mitigation_data["description"] = description_div.get_text(" ", strip=True)

        # Parse techniques addressed by mitigation
        techniques_table: Union[Tag, None] = soup.find("h2", string="Techniques Addressed by Mitigation").find_next("table")
        if techniques_table:
            latest_domain = None
            latest_main_technique_id = None
            for row in techniques_table.find("tbody").find_all("tr"):
                cells = row.find_all("td")
                if len(cells) == 5:
                    domain = cells[0].get_text(strip=True) if cells[0].get_text(strip=True) else latest_domain
                    latest_domain = domain

                    main_technique_id = cells[1].find("a").get_text(strip=True) if cells[1].find("a") else latest_main_technique_id
                    latest_main_technique_id = main_technique_id
                    sub_technique_id = cells[2].find("a").get_text(strip=True) if cells[2].find("a") else None
                    if sub_technique_id:
                        technique_id = f"{main_technique_id}{sub_technique_id}"
                        technique_url = f"https://attack.mitre.org/techniques/{main_technique_id}/{sub_technique_id.replace('.', '')}/"
                    else:
                        technique_id = main_technique_id
                        technique_url = f"https://attack.mitre.org/techniques/{main_technique_id}/"

                    main_technique_name = cells[3].find("a").get_text(strip=True)
                    sub_technique_name = cells[3].find_all("a")[1].get_text(strip=True) if len(cells[3].find_all("a")) > 1 else None
                    if sub_technique_name:
                        technique_name = f"{main_technique_name} ({sub_technique_name})" 
                    else:
                        technique_name = main_technique_name

                    technique_use = cells[4].get_text(" ", strip=True)
                    
                    mitigation_data["techniques_addressed_by_mitigation"].append({
                        "domain": domain,
                        "id": technique_id,
                        "name": technique_name,
                        "use": technique_use,
                        "url": technique_url
                    })

        # Parse references
        references_div: Union[Tag, None] = soup.find("h2", string="References").find_next("div") if soup.find("h2", string="References") else None
        reference_number: int = 1
        if references_div:
            for li in references_div.find_all("li"):
                a_tag = li.find("a")
                if a_tag:
                    reference_text = li.get_text(" ", strip=True)
                    reference_href = a_tag["href"]
                    # Add the reference to the references dictionary; the key is the reference number
                    mitigation_data["references"][reference_number] = {
                        "text": reference_text,
                        "url": reference_href
                    }
                    reference_number += 1

        return mitigation_data