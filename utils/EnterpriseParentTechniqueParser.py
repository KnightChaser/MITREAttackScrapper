# utils/EnterpriseParentTechniqueParser.py
import httpx
from bs4 import BeautifulSoup
from typing import Dict, Any, List
from datetime import datetime

def get_enterprise_parent_techniques(technique_id: str) -> Dict[str, Any]:
    """
    Parse the specific parent Enterprise MITRE ATT&CK technique
    """
    request_url = f"https://attack.mitre.org/techniques/{technique_id}/"
    response = httpx.get(request_url)
    soup = BeautifulSoup(response.text, "html.parser")

    # Get the data card body
    card_body = soup.select_one("#v-attckmatrix > div.row > div > div > div > div:nth-child(2) > div.col-md-4 > div.card > div.card-body")

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
        "last_modified":        None
    }

    def get_text_after_span(card_body: BeautifulSoup, label: str) -> str:
        """
        Helper function to extract the text after the span element with the given label
        Since there may be multiple text elements, we iterate over the siblings of the span element
        Plus, we remove any leading/trailing whitespaces from the text
        """
        span = card_body.find("span", string=lambda text: text and text.strip().startswith(label))
        if span:
            return span.next_sibling.strip()
        return ""

    def get_links_after_span(card_body: BeautifulSoup, label: str) -> List[Dict[str, str]]:
        """
        Helper function to extract the links after the span element with the given label
        Since there may be multiple links, we iterate over the siblings of the span element
        Plus, we extract the name and URL of each link
        """
        span = card_body.find("span", string=lambda text: text and text.strip().startswith(label))
        links = []
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
    platforms_text = get_text_after_span(card_body, "Platforms:")
    if platforms_text:
        technique_data["platforms"] = [platform.strip() for platform in platforms_text.split(",")]

    # Parse permissions required
    permissions_text = get_text_after_span(card_body, "Permissions Required:")
    if permissions_text:
        technique_data["permission_required"] = [permission.strip() for permission in permissions_text.split(",")]

    # Parse version
    version_text = get_text_after_span(card_body, "Version:")
    if version_text:
        technique_data["version"] = version_text

    # Parse created date
    created_text = get_text_after_span(card_body, "Created:")
    if created_text:
        technique_data["created"] = datetime.strptime(created_text, "%d %B %Y")

    # Parse last modified date
    last_modified_text = get_text_after_span(card_body, "Last Modified:")
    if last_modified_text:
        technique_data["last_modified"] = datetime.strptime(last_modified_text, "%d %B %Y")

    return technique_data

print(get_enterprise_parent_techniques("T1548"))
