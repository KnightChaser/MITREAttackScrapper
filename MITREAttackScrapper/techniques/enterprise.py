# MITREAttackScrapper/technique/enterprise.py
import httpx
import re
from bs4 import BeautifulSoup, Tag
from typing import Dict, Any, List, Union
from datetime import datetime
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from superclass import MITREAttackInformation
from utils.scrapping_helper import get_text_after_span, get_links_after_span
from utils.mitre_id_validator import validate_mitre_technique_id

class MITREAttackEnterpriseTechniques(MITREAttackInformation):
    """
    A class containing methods to parse MITRE ATT&CK Enterprise techniques.
    """

    @staticmethod
    def get_list() -> List[Dict[str, Any]]:
        """
        Get the list of all MITRE ATT&CK techniques for Enterprise.

        The structure of the returned data is as follows:
        ```json
        [
            {
                "id": "T0001",
                "name": "Technique Name",
                "description": "Technique Description",
                "url": "https://attack.mitre.org/techniques/T0001/",
                "sub_techniques": [
                    {
                        "id": "T0001.001",
                        "name": "Sub-Technique Name",
                        "description": "Sub-Technique Description",
                        "url": "https://attack.mitre.org/techniques/T0001/T0001.001/"
                    },
                    ...
                ]
            },
            ...
        ]
        ```
        """
        target_url = "https://attack.mitre.org/techniques/enterprise/"
        response = httpx.get(target_url)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch data from {target_url}. Status code: {response.status_code}")
        data = []

        # Extract the <table> element from the response
        soup = BeautifulSoup(response.text, "html.parser")
        table = soup.find("table")

        rows = table.find_all("tr", class_=["technique", "sub technique"])
        for row in rows:
            if "technique" == row["class"][0]:
                # Parse the parent MITRE ATT&CK technique
                technique_link = row.find("a", href=True)
                technique_id = technique_link.get_text(strip=True)
                technique_url = "https://attack.mitre.org" + technique_link['href']

                cells = row.find_all("td")
                technique_name = cells[1].get_text(strip=True)
                technique_description = cells[2].get_text(strip=True)
                data.append({
                    "id": technique_id,
                    "name": technique_name,
                    "description": technique_description,
                    "url": technique_url,
                    "sub_techniques": []
                })

            elif "sub" == row["class"][0] and "technique" == row["class"][1]:
                # Parse the associated sub-techniques for the parent MITRE ATT&CK technique
                sub_technique_link = row.find("a", href=True)
                sub_technique_id = data[-1]["id"] + sub_technique_link.get_text(strip=True)
                sub_technique_url = "https://attack.mitre.org" + sub_technique_link['href']

                cells = row.find_all("td")
                sub_technique_name = cells[2].get_text(strip=True)
                sub_technique_description = cells[3].get_text(strip=True)
                data[-1]["sub_techniques"].append({
                    "id": sub_technique_id,
                    "name": sub_technique_name,
                    "description": sub_technique_description,
                    "url": sub_technique_url
                })

        return data
    
    @staticmethod
    @validate_mitre_technique_id
    def get(technique_id: str) -> Dict[str, Any]:
        """
        Given a technique ID, return the technique information.

        `technique_id` can be either a parent technique ID or a child technique ID. (e.g. `T1548` or `T1548.001`)
        It calls get_parent_technique() if the technique ID is a parent technique ID, or get_child_technique() if the technique ID is a child technique ID.

        No matter the technique ID is a parent or child technique, the returned data structure has the same basic data structure. Here's an example:
        ```json
        {
            "id": "T0001.001",
            "parent_technique_id": "T0001",
            "tactics": [
                {
                    "name": "Tactic Name",
                    "url": "https://attack.mitre.org/tactics/Tactic Name/"
                },
                ...
            ],
            "platforms": ["Platform1", "Platform2", ...],
            "permission_required": ["Permission1", "Permission2", ...],
            "version": "Version",
            "created": "Created Date",
            "last_modified": "Last Modified Date",
            "procedures": [
                {
                    "id": "Procedure ID",
                    "name": "Procedure Name",
                    "description": "Procedure Description"
                },
                ...
            ],
            "mitigations": [
                {
                    "id": "Mitigation ID",
                    "name": "Mitigation Name",
                    "description": "Mitigation Description"
                },
                ...
            ],
            "detection": [
                {
                    "id": "Detection ID",
                    "data_source": "Data Source",
                    "data_component": "Data Component",
                    "detects": "Detects"
                },
                ...
            ],
            "description": "Technique Description",
            "references": {
                1 : {
                    "text": "Reference Text",
                    "url": "Reference URL"
                },
                ...
            }
        }
        ```
        """
        if not technique_id:
            raise ValueError("Technique ID is required")
        
        # Regex check for the technique ID
        if not re.match(r"T\d{4}(\.\d{3})?", technique_id):
            raise ValueError("Invalid technique ID format. Please provide a valid technique ID.")
        
        if "." in technique_id:
            # Child technique
            parent_technique_id, child_technique_id = technique_id.split(".")
            return MITREAttackEnterpriseTechniques.get_child_technique(parent_technique_id=parent_technique_id, 
                                                                       child_technique_id=child_technique_id)
        else:
            # Parent technique
            return MITREAttackEnterpriseTechniques.get_parent_technique(technique_id=technique_id)

    @staticmethod
    @validate_mitre_technique_id
    def get_child_technique(parent_technique_id: str, child_technique_id: str) -> Dict[str, Any]:
        """
        Parse the specific child Enterprise MITRE ATT&CK Enterprise technique for the given child technique

        This content may have one or multiple references. The references are stored in a dictionary where the key is the reference number.
        They can be found by number indices such as `[1]`, `[2]`, `[3]`, etc. in the original MITRE ATT&CK page.

        The structure of the returned data is as follows:
        ```json
        {
            "id": "T0001.001",
            "parent_technique_id": "T0001",
            "tactics": [
                {
                    "name": "Tactic Name",
                    "url": "https://attack.mitre.org/tactics/Tactic Name/"
                },
                ...
            ],
            "platforms": ["Platform1", "Platform2", ...],
            "permission_required": ["Permission1", "Permission2", ...],
            "version": "Version",
            "created": "Created Date",
            "last_modified": "Last Modified Date",
            "procedures": [
                {
                    "id": "Procedure ID",
                    "name": "Procedure Name",
                    "description": "Procedure Description"
                },
                ...
            ],
            "mitigations": [
                {
                    "id": "Mitigation ID",
                    "name": "Mitigation Name",
                    "description": "Mitigation Description"
                },
                ...
            ],
            "detection": [
                {
                    "id": "Detection ID",
                    "data_source": "Data Source",
                    "data_component": "Data Component",
                    "detects": "Detects"
                },
                ...
            ],
            "description": "Technique Description",
            "references": {
                1 : {
                    "text": "Reference Text",
                    "url": "Reference URL"
                },
                ...
            }
        }
        """
        # Parameter existence check
        if not parent_technique_id or not child_technique_id:
            raise ValueError("Parent and child technique IDs are required")

        request_url = f"https://attack.mitre.org/techniques/{parent_technique_id}/{child_technique_id}/"
        response: httpx.Response = httpx.get(request_url)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch data from {request_url}. Status code: {response.status_code}")
        soup: BeautifulSoup = BeautifulSoup(response.text, "html.parser")

        # Get the data card body
        card_body: Union[Tag, None] = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(2) > div.col-md-4 > div.card > div.card-body")

        if not card_body:
            return {"error": "Card body not found"}

        # Initialize the result dictionary
        technique_data: Dict[str, Any] = {
            "id":                   child_technique_id,
            "parent_technique_id":  parent_technique_id,
            "tactics":              [],
            "platforms":            [],
            "permission_required":  [],
            "version":              "",
            "created":              None,
            "last_modified":        None,
            "procedures":           [],
            "mitigations":          [],
            "detection":            [],
            "description":          "",
            "references":           [],
        }

        # Parse tactics
        technique_data["tactics"] = get_links_after_span(card_body, "Tactics:")

        # Parse platforms
        platforms_text: str = get_text_after_span(card_body, "Platforms:")
        if platforms_text:
            technique_data["platforms"] = [platform.strip() for platform in platforms_text.split(",")]

        # Parse permissions required
        permissions_text: str = get_text_after_span(card_body, "Permissions Required:")
        if permissions_text:
            technique_data["permission_required"] = [permission.strip() for permission in permissions_text.split(",")]

        # Parse version
        version_text: str = get_text_after_span(card_body, "Version:")
        if version_text:
            technique_data["version"] = version_text

        # Parse created date
        created_text: str = get_text_after_span(card_body, "Created:")
        if created_text:
            technique_data["created"] = datetime.strptime(created_text, "%d %B %Y")

        # Parse last modified date
        last_modified_text: str = get_text_after_span(card_body, "Last Modified:")
        if last_modified_text:
            technique_data["last_modified"] = datetime.strptime(last_modified_text, "%d %B %Y")

        # Parse procedures (assumed to be the sub-techniques table)
        # Next object(div)'s <table> tag after a h2 tag whose inner text is "Procedure Examples"
        procedures_table: Union[Tag, None] = soup.find("h2", string="Procedure Examples").find_next("table")
        if procedures_table:
            for row in procedures_table.find("tbody").find_all("tr"):
                cells = row.find_all("td")
                procedure_id = cells[0].get_text(strip=True)
                procedure_name = cells[1].get_text(strip=True)
                description = cells[2].get_text(strip=True)
                technique_data["procedures"].append({
                    "id": procedure_id,
                    "name": procedure_name,
                    "description": description
                })

        # Parse mitigations
        # Next object(div)'s <table> tag after a h2 tag whose inner text is "Mitigations"
        mitigation_table: Union[Tag, None] = soup.find("h2", string="Mitigations").find_next("table")
        if mitigation_table:
            for row in mitigation_table.find("tbody").find_all("tr"):
                cells = row.find_all("td")
                mitigation_id = cells[0].get_text(strip=True)
                mitigation_name = cells[1].get_text(strip=True)
                mitigation_description = cells[2].get_text(strip=True)
                technique_data["mitigations"].append({
                    "id": mitigation_id,
                    "name": mitigation_name,
                    "description": mitigation_description
                })

        # Parse detection
        # Next object(div)'s <table> tag after a h2 tag whose inner text is "Detection"
        detection_table: Union[Tag, None] = soup.find("h2", string="Detection").find_next("table")
        if detection_table:
            for row in detection_table.find("tbody").find_all("tr"):
                cells = row.find_all("td")
                if len(cells) == 4:
                    detection_id = cells[0].get_text(strip=True)
                    data_source = cells[1].get_text(strip=True)
                    data_component = cells[2].get_text(strip=True)
                    detects = cells[3].get_text(strip=True)
                    technique_data["detection"].append({
                        "id": detection_id,
                        "data_source": data_source,
                        "data_component": data_component,
                        "detects": detects
                    })

        # Parse description
        description_div: Union[Tag, None] = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(2) > div.col-md-8 > div.description-body")
        if description_div:
            paragraphs = description_div.find_all("p")
            description_text = " ".join(p.get_text(" ", strip=True) for p in paragraphs)
            technique_data["description"] = description_text

        # Parse references
        # Next object of "h2" tag with "References" inner text
        references_div: Union[Tag, None] = soup.find("h2", string="References").find_next_sibling("div")
        references_number: int = 1
        if references_div:
            references = {}
            for li in references_div.find_all("li"):
                a_tag = li.find("a")
                if a_tag:
                    reference_text = li.get_text(" ", strip=True)
                    reference_url = a_tag["href"]
                    # Add the reference to the references dictionary; the key is the reference number
                    references[references_number] = {
                        "text": reference_text,
                        "url": reference_url
                    }
                    references_number += 1
            technique_data["references"] = references

        return technique_data

    @staticmethod
    @validate_mitre_technique_id
    def get_parent_technique(technique_id: str) -> Dict[str, Any]:
        """
        Parse the specific child Enterprise MITRE ATT&CK Enterprise technique for the given parent technique

        This content may have one or multiple references. The references are stored in a dictionary where the key is the reference number.
        They can be found by number indices such as `[1]`, `[2]`, `[3]`, etc. in the original MITRE ATT&CK page.

        The structure of the returned data is as follows:
        ```json
        {
            "id": "T0001",
            "sub_techniques": [
                {
                    "id": "T0001.001",
                    "name": "Sub-Technique Name",
                    "description": "Sub-Technique Description",
                    "url": "https://attack.mitre.org/techniques/T0001/T0001.001/"
                },
                ...
            ],
            "tactics": [
                {
                    "name": "Tactic Name",
                    "url": "https://attack.mitre.org/tactics/Tactic Name/"
                },
                ...
            ],
            "platforms": ["Platform1", "Platform2", ...],
            "permission_required": ["Permission1", "Permission2", ...],
            "version": "Version",
            "created": "Created Date",
            "last_modified": "Last Modified Date",
            "mitigations": [
                {
                    "id": "Mitigation ID",
                    "name": "Mitigation Name",
                    "description": "Mitigation Description"
                },
                ...
            ],
            "detection": [
                {
                    "id": "Detection ID",
                    "data_source": "Data Source",
                    "data_component": "Data Component",
                    "detects": "Detects"
                },
                ...
            ],
            "description": "Technique Description",
            "references": {
                1 : {
                    "text": "Reference Text",
                    "url": "Reference URL"
                },
                ...
            }
        }
        """
        # Parameter existence check
        if not technique_id:
            raise ValueError("Technique ID is required")

        request_url = f"https://attack.mitre.org/techniques/{technique_id}/"
        response: httpx.Response = httpx.get(request_url)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch data from {request_url}. Status code: {response.status_code}")
        soup: BeautifulSoup = BeautifulSoup(response.text, "html.parser")

        # Get the data card body
        card_body: Union[Tag, None] = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(2) > div.col-md-4 > div.card > div.card-body")

        if not card_body:
            return {"error": "Card body not found"}

        # Initialize the result dictionary
        technique_data: Dict[str, Any] = {
            "id":                   technique_id,
            "sub_techniques":       [],
            "tactics":              [],
            "platforms":            [],
            "permission_required":  [],
            "version":              "",
            "created":              None,
            "last_modified":        None,
            "mitigations":          [],
            "detection":            [],
            "description":          "",
            "references":           {}
        }

        def get_text_after_span(card_body: Tag, label: str) -> str:
            """
            Helper function to extract the text after the span element with the given label.
            Since there may be multiple text elements, we iterate over the siblings of the span element.
            Plus, we remove any leading/trailing whitespaces from the text.
            """
            span: Union[Tag, None] = card_body.find("span", string=lambda text: text and text.strip().startswith(label))
            if span and span.next_sibling:
                return span.next_sibling.strip()
            return ""

        def get_links_after_span(card_body: Tag, label: str) -> List[Dict[str, str]]:
            """
            Helper function to extract the links after the span element with the given label.
            Since there may be multiple links, we iterate over the siblings of the span element.
            Plus, we extract the name and URL of each link.
            """
            span: Union[Tag, None] = card_body.find("span", string=lambda text: text and text.strip().startswith(label))
            links: List[Dict[str, str]] = []
            if span:
                for a in span.find_next_siblings("a"):
                    links.append({
                        "name": a.get_text(strip=True),
                        "url": "https://attack.mitre.org" + a["href"]
                    })
            return links

        # Parse sub-techniques
        technique_data["sub_techniques"] = get_links_after_span(card_body, "Sub-techniques:")

        # Parse tactics
        technique_data["tactics"] = get_links_after_span(card_body, "Tactics:")

        # Parse platforms
        platforms_text: str = get_text_after_span(card_body, "Platforms:")
        if platforms_text:
            technique_data["platforms"] = [platform.strip() for platform in platforms_text.split(",")]

        # Parse permissions required
        permissions_text: str = get_text_after_span(card_body, "Permissions Required:")
        if permissions_text:
            technique_data["permission_required"] = [permission.strip() for permission in permissions_text.split(",")]

        # Parse version
        version_text: str = get_text_after_span(card_body, "Version:")
        if version_text:
            technique_data["version"] = version_text

        # Parse created date
        created_text: str = get_text_after_span(card_body, "Created:")
        if created_text:
            technique_data["created"] = datetime.strptime(created_text, "%d %B %Y")

        # Parse last modified date
        last_modified_text: str = get_text_after_span(card_body, "Last Modified:")
        if last_modified_text:
            technique_data["last_modified"] = datetime.strptime(last_modified_text, "%d %B %Y")

        # Parse mitigations
        mitigation_table: Union[Tag, None] = soup.find("h2", string="Mitigations").find_next("table")
        if mitigation_table:
            for row in mitigation_table.find("tbody").find_all("tr"):
                cells = row.find_all("td")
                mitigation_id = cells[0].get_text(strip=True)
                mitigation_name = cells[1].get_text(strip=True)
                mitigation_description = cells[2].get_text(strip=True)
                technique_data["mitigations"].append({
                    "id": mitigation_id,
                    "name": mitigation_name,
                    "description": mitigation_description
                })

        # Parse detection
        # Next object(div)'s <table> tag after a h2 tag whose inner text is "Detection"
        detection_table: Union[Tag, None] = soup.find("h2", string="Detection").find_next("table")
        if detection_table:
            latest_detection_id = None              # To store the latest detection ID to fill in the missing detection IDs
            latest_detection_data_source = None     # To store the latest detection data source to fill in the missing detection data sources
            for row in detection_table.find("tbody").find_all("tr"):
                cells = row.find_all("td")
                if len(cells) == 4:
                    detection_id = cells[0].get_text(strip=True)
                    data_source = cells[1].get_text(strip=True)
                    data_component = cells[2].get_text(strip=True)
                    latest_detection_id = detection_id  
                    latest_detection_data_source = data_source
                    detects = cells[3].get_text(strip=True)
                    technique_data["detection"].append({
                        "id": detection_id,
                        "data_source": data_source,
                        "data_component": data_component,
                        "detects": detects
                    })

        # Parse description
        description_div: Union[Tag, None] = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(2) > div.col-md-8 > div.description-body")
        if description_div:
            paragraphs = description_div.find_all("p")
            description_text = " ".join(p.get_text(" ", strip=True) for p in paragraphs)
            technique_data["description"] = description_text

        # Parse references
        # Next object of "h2" tag with "References" inner text
        references_div: Union[Tag, None] = soup.find("h2", string="References").find_next_sibling("div")
        reference_number: int = 1
        if references_div:
            references = {}
            for li in references_div.find_all("li"):
                a_tag = li.find("a")
                if a_tag:
                    reference_text = li.get_text(" ", strip=True)
                    reference_url = a_tag["href"]
                    # Add the reference to the references dictionary; the key is the reference number
                    references[reference_number] = {
                        "text": reference_text,
                        "url": reference_url
                    }
                    reference_number += 1
            technique_data["references"] = references

        return technique_data