# MITREAttackScrapper/tactics/enterprise.py

import httpx
from bs4 import BeautifulSoup, Tag
from typing import List, Dict, Any, Union
from datetime import datetime

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from superclass import MITREAttackInformation
from utils.scrapping_helper import get_text_after_span 
from utils.mitre_id_validator import validate_mitre_tactic_id

class MITREAttackEnterpriseTactics(MITREAttackInformation):
    """A class containing methods to parse MITRE ATT&CK Enterprise Tactics."""

    @staticmethod
    def get_list() -> List[Dict[str, Any]]:
        """
        Get the list of all MITRE ATT&CK tactics for Enterprise.

        :return: A list of dictionaries containing tactic information.
        :rtype: List[Dict[str, Any]]
        :raises RuntimeError: If there's a failure in fetching data from the MITRE ATT&CK website.

        :Example:

        .. code-block:: python

            [
                {
                    "id": "TA0001",
                    "name": "Tactic Name",
                    "description": "Tactic Description",
                    "url": "https://attack.mitre.org/tactics/TA0001/",
                },
                # ... more tactic entries
            ]
        """
        target_url = "https://attack.mitre.org/tactics/enterprise/"
        response = httpx.get(target_url)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch data from {target_url}")
        data = []

        # Extract the <table> element containing the tactics
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
    @validate_mitre_tactic_id
    def get(tactic_id: str) -> Dict[str, Any]:
        """
        Get the details of a specific MITRE ATT&CK tactic for Enterprise.

        :param tactic_id: The ID of the specific MITRE ATT&CK tactic.
        :type tactic_id: str
        :return: A dictionary containing the details of the specified MITRE ATT&CK tactic.
        :rtype: Dict[str, Any]
        :raises ValueError: If the provided tactic ID is invalid.
        :raises RuntimeError: If the data fetch from the MITRE ATT&CK website fails.
        
        :Example:

        .. code-block:: python

            {
                "id": "TA0001",
                "name": "Tactic Name",
                "created": "Created Date",
                "last_modified": "Last Modified Date",
                "url": "https://attack.mitre.org/tactics/TA0001/",
                "description": "Tactic Description",
                "techniques": [
                    {
                        "id": "T1234.001",
                        "name": "Technique Name",
                        "url": "https://attack.mitre.org/techniques/T1234/001/",
                        "description": "Technique Description"
                    }
                ]
            }
        """
        target_url = f"https://attack.mitre.org/tactics/{tactic_id}/"
        response = httpx.get(target_url)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch data from {target_url}")

        soup = BeautifulSoup(response.text, "html.parser")
        
        tactic_data = {
            "id": tactic_id,
            "name": "",
            "created": None,
            "last_modified": None,
            "url": target_url,
            "description": "",
            "techniques": []
        }

        # Parse the name
        name = soup.find("h1")
        if name:
            tactic_data["name"] = name.text.strip()

        # Parse the description
        description_div = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(2) > div.col-md-8 > div.description-body")
        if description_div:
            paragraphs = description_div.find_all("p")
            description_text = " ".join(p.get_text(" ", strip=True) for p in paragraphs)
            tactic_data["description"] = description_text

        # Parse created and last modified dates
        card_body = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(2) > div.col-md-4 > div.card > div.card-body")
        if card_body:
            created_text = get_text_after_span(card_body, "Created:")
            last_modified_text = get_text_after_span(card_body, "Last Modified:")

            if created_text:
                tactic_data["created"] = datetime.strptime(created_text, "%d %B %Y").strftime("%Y-%m-%d")
            if last_modified_text:
                tactic_data["last_modified"] = datetime.strptime(last_modified_text, "%d %B %Y").strftime("%Y-%m-%d")

        # Parse techniques
        techniques_table: Union[Tag, None] = soup.find("h2", string="Techniques").find_next("table")
        if techniques_table:
            latest_main_technique_id = None
            for row in techniques_table.find("tbody").find_all("tr"):
                cells = row.find_all("td")
                if "technique" == row["class"][0]:
                    # parsing main technique
                    main_technique_id: str = cells[0].find("a").text.strip()
                    latest_main_technique_id = main_technique_id
                    technique_name: str = cells[1].find("a").text.strip()
                    technique_url = f"https://attack.mitre.org{cells[1].find('a')['href']}"
                    technique_description = cells[2].get_text(strip=True)
                    tactic_data["techniques"].append({
                        "id": main_technique_id,
                        "name": technique_name,
                        "url": technique_url,
                        "description": technique_description
                    })

                elif "sub" == row["class"][0] and "technique" in row["class"]:
                    # parsing sub-technique
                    sub_technique_id: str = f"{latest_main_technique_id}{cells[1].find('a').text.strip()}"
                    technique_name: str = cells[2].find("a").text.strip()
                    technique_url = f"https://attack.mitre.org{cells[2].find('a')['href']}"
                    technique_description = cells[3].get_text(strip=True)
                    tactic_data["techniques"].append({
                        "id": sub_technique_id,
                        "name": technique_name,
                        "url": technique_url,
                        "description": technique_description
                    })
        return tactic_data