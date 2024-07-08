# mitre_scrapper.py

import httpx
import json
from bs4 import BeautifulSoup

def get_mitre_data():
    """
    Scrapping the MITRE ATT&CK technique for Enterprise list and organizing the data into a JSON format.
    """
    target_url = "https://attack.mitre.org/techniques/enterprise/"
    response = httpx.get(target_url)
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

        # Further, we will have to parse each technique's detailed information from the respective URL

    print(json.dumps(data, indent=2))

get_mitre_data()

