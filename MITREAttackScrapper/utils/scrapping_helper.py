# MITREAttackScrapper/utils/scrapping_helper.py
from bs4.element import Tag
from typing import Union, List, Dict

def get_text_after_span(card_body: Tag, label: str) -> str:
    """
    Helper function to extract the text after the span element with the given label.

    For example, It can be used to extract the value after a label in the following format:
    ```html
    <span>Label:</span> Value
    ```
    """
    span: Union[Tag, None] = card_body.find("span", string=lambda text: text and text.strip().startswith(label))
    if span and span.next_sibling:
        return span.next_sibling.strip()
    return ""

def get_links_after_span(card_body: Tag, label: str) -> List[Dict[str, str]]:
    """
    Helper function to extract the links after the span element with the given label.

    For example, It can be used to extract the links after a label in the following format:
    ```html
    <span>Label:</span> 
        <a href="https://example.com">Link 1</a> 
        <a href="https://example.com">Link 2</a>
    ```
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