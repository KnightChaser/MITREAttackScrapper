# utils/EnterpriseChildTechniqueParser.py
import httpx
from bs4 import BeautifulSoup, Tag
from typing import Dict, Any, List, Union
from datetime import datetime

def get_enterprise_child_techniques(technique_parent_id: str, technique_child_id: str) -> Dict[str, Any]:
    """
    Parse the specific child Enterprise MITRE ATT&CK technique
    """
    request_url = f"https://attack.mitre.org/techniques/{technique_parent_id}/{technique_child_id}/"
    response: httpx.Response = httpx.get(request_url)
    soup: BeautifulSoup = BeautifulSoup(response.text, "html.parser")

    # Get the data card body
    card_body: Union[Tag, None] = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(2) > div.col-md-4 > div.card > div.card-body")
    
    if not card_body:
        return {"error": "Card body not found"}

    # Initialize the result dictionary
    technique_data: Dict[str, Any] = {
        "id":                   technique_child_id,
        "parent_technique_id":  technique_parent_id,
        "tactics":              [],
        "platforms":            [],
        "permission_required":  [],
        "version":              "",
        "created":              None,
        "last_modified":        None,
        "procedures":           [],
        "mitigations":          [],
        "detection":            [],
        "description":          {
            "text": "",
            "annotations": {}
        }
    }

    def get_text_after_span(card_body: Tag, label: str) -> str:
        """
        Helper function to extract the text after the span element with the given label.
        """
        span: Union[Tag, None] = card_body.find("span", string=lambda text: text and text.strip().startswith(label))
        if span and span.next_sibling:
            return span.next_sibling.strip()
        return ""

    def get_links_after_span(card_body: Tag, label: str) -> List[Dict[str, str]]:
        """
        Helper function to extract the links after the span element with the given label.
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
    procedures_table: Union[Tag, None] = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(4) > table")
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
    mitigation_table: Union[Tag, None] = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(4) > table")
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
    detection_table: Union[Tag, None] = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(8) > table")
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
        annotations = {}
        for ref in description_div.find_all("span", class_="scite-citeref-number"):
            ref_id = ref.get_text(strip=True).strip("[]")
            ref_title = ref["title"]
            ref_href = ref.find("a")["href"]
            annotations[ref_id] = {
                "title": ref_title,
                "href": ref_href
            }
        technique_data["description"]["text"] = description_text
        technique_data["description"]["annotations"] = annotations

    return technique_data

print(get_enterprise_child_techniques("T1548", "001"))
