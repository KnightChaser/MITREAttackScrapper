# MITREAttackScrapper/cti/groups.py

import httpx
from bs4 import BeautifulSoup, Tag
from typing import List, Dict, Any, Union
from datetime import datetime

from ..superclass import MITREAttackInformation
from ..utils.mitre_id_validator import validate_mitre_group_id
from ..utils.scrapping_helper import get_text_after_span

class MITREAttackCTIGroups(MITREAttackInformation):
    """
    A class containing methods to parse MITRE ATT&CK Groups.
    """

    @staticmethod
    def get_list() -> List[Dict[str, Any]]:
        """
        Get the list of all MITRE ATT&CK Groups.

        :return: A list of dictionaries containing information about each MITRE ATT&CK Group.
        :rtype: List[Dict[str, Any]]
        :raises RuntimeError: If the data fetch from the MITRE ATT&CK website fails.

        Example
        -------
        The structure of the returned data is as follows:

        .. code-block:: python

            [
                {
                    "id": "G0001",
                    "name": "Group Name",
                    "associated_groups": "Associated Groups",
                    "description": "Group Description",
                    "url": "https://attack.mitre.org/groups/G0001/",
                },
                # ... more group entries
            ]
        """

        target_url = "https://attack.mitre.org/groups/"
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
                group_id = cells[0].text.strip()
                group_name = cells[1].text.strip()
                associated_groups = cells[2].text.strip()
                description = cells[3].text.strip()
                group_url = cells[0].find("a")["href"]
                data.append({
                    "id": group_id,
                    "name": group_name,
                    "associated_groups": associated_groups,
                    "description": description,
                    "url": group_url,
                })

        return data
    

    @staticmethod
    @validate_mitre_group_id
    def get(group_id: str) -> Dict[str, Any]:
        """
        Get the details of a specific MITRE ATT&CK Group.

        :param group_id: The ID of the MITRE ATT&CK Group.
        :type group_id: str
        :return: A dictionary containing information about the specific MITRE ATT&CK Group.
        :rtype: Dict[str, Any]
        :raises ValueError: If the provided group ID format is invalid.
        :raises RuntimeError: If the data fetch from the MITRE ATT&CK website fails.

        Example
        -------
        The structure of the returned data is as follows:

        .. code-block:: python

            {
                "id": "G0001",
                "name": "Group Name",
                "contributors": ["name 1", "name 2", ...],
                "version": "Version",
                "created": "Created Date",
                "last_modified": "Last Modified Date",
                "description": "Group Description",
                "url": "https://attack.mitre.org/groups/G0001/",
                "associated_group_descriptions": [
                    {
                        "name": "Associated Group",
                        "description": "Associated Group Description"
                    },
                    # ... more associated groups
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
                        "name": "Software Name",
                        "url": "https://attack.mitre.org/software/S0001/",
                        "references": ["Reference URL 1", "Reference URL 2", ...],
                        "techniques": [
                            {
                                "name": "Technique Name",
                                "url": "https://attack.mitre.org/techniques/T0001/",
                            },
                            # ... more techniques
                        ]
                    },
                    # ... more software entries
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
        
        target_url = f"https://attack.mitre.org/groups/{group_id}/"
        response = httpx.get(target_url)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch data from {target_url}")
    
        soup = BeautifulSoup(response.text, "html.parser")
        group_data = {
            "id": group_id,
            "name": None,
            "contributors": [],
            "version": None,
            "created": None,
            "last_modified": None,
            "description": "",
            "url": target_url,
            "associated_group_descriptions": [],
            "techniques_used": [],
            "software": [],
            "references": {}
        }

        # Extract the group name
        group_data["name"] = soup.find("h1").text.strip()

        # Extract the description
        description_tag: Union[Tag, None] = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(2) > div.col-md-8 > div > p")
        group_data["description"] = description_tag.text.strip() if description_tag else None

        # Extract contributors
        contributors_tag = soup.find("span", string="Contributors").parent if soup.find("span", string="Contributors") else None
        contributors = contributors_tag.text.replace("Contributors:", "").strip().split(";") if contributors_tag else []
        group_data["contributors"] = [contributor.strip() for contributor in contributors]

        # Extract version
        version_tag = soup.find("span", string="Version").parent if soup.find("span", string="Version") else None
        group_data["version"] = version_tag.text.replace("Version:", "").strip() if version_tag else None

        # Extract created date
        card_body: Union[Tag, None] = soup.select_one("div.card > div.card-body")
        group_data["created"] = get_text_after_span(card_body, "Created:")
        group_data["created"] = datetime.strptime(group_data["created"], "%d %B %Y").strftime("%Y-%m-%d")
        group_data["last_modified"] = get_text_after_span(card_body, "Last Modified:")
        group_data["last_modified"] = datetime.strptime(group_data["last_modified"], "%d %B %Y").strftime("%Y-%m-%d")

        # Extract associated group descriptions
        associated_group_descriptions = []
        associated_group_table = soup.find("table", class_="table table-bordered table-alternate mt-2") if soup.find("table", class_="table table-bordered table-alternate mt-2") else None
        if associated_group_table:
            for row in associated_group_table.find_all("tr")[1:]:
                cells = row.find_all("td")
                if len(cells) == 2:
                    group_name = cells[0].text.strip()
                    description = cells[1].text.strip()
                    associated_group_descriptions.append({"name": group_name, 
                                                          "description": description})
        group_data["associated_group_descriptions"] = associated_group_descriptions

        # Extract techniques used (if any, as an example)
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

        group_data["techniques_used"] = techniques_used

        # Extract software used (if any, as an example)
        # This section depends on the structure of the page, adjust selectors as needed
        software_used = []
        software_table = soup.find("h2", string="Software").find_next("table") if soup.find("h2", string="Software") else None
        if software_table:
            for row in software_table.find_all("tr"):
                cells: List[Tag] = row.find_all("td")
                if len(cells) == 4:
                    software_id = cells[0].find("a").get_text(strip=True)
                    software_name = cells[1].find("a").get_text(strip=True)
                    software_url = cells[1].find("a")["href"]
                    references = [a_tag["href"] for a_tag in cells[2].find_all("a")]
                    techniques_name = [a_tag.get_text(strip=True) for a_tag in cells[3].find_all("a")]
                    techniques_url = [a_tag["href"] for a_tag in cells[3].find_all("a")]
                    software_used.append({
                        "id": software_id,
                        "name": software_name,
                        "url": software_url,
                        "references": references,
                        "techniques": [{"name": name, "url": f"https://attack.mitre.org{url}"} for name, url in zip(techniques_name, techniques_url)]
                    })
                    
        group_data["software"] = software_used

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
                    group_data["references"][reference_number] = {
                        "text": reference_text,
                        "url": reference_href
                    }
                    reference_number += 1

        return group_data