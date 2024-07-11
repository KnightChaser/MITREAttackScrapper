.. MITREAttackScrapper documentation master file, created by
   sphinx-quickstart on Wed Jul 10 16:16:01 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to MITREAttackScrapper's documentation!
===============================================

MITREAttackScrapper is a Python package designed to scrape and process MITRE ATT&CK information, presenting it in a dictionary format that is highly useful for various data processing tasks in Python 3. This package simplifies the extraction and utilization of MITRE ATT&CK data, making it an invaluable resource for cybersecurity professionals and researchers.

Features:
---------
- Scrape and process data from MITRE ATT&CK.
- Present data in a dictionary format, ideal for use in Python 3.
- Facilitate easy access and manipulation of cybersecurity data.

Note:
-----
MITREAttackScrapper is being developed by @KnightChaser
for experimental purposes. It is not officially affiliated with MITRE.

Getting Started:
----------------
To get started with MITREAttackScrapper, you can refer to the installation and usage guides provided in the documentation.

.. toctree::
   :maxdepth: 4
   :caption: Contents:

   source/modules

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Installation
============

You can install MITREAttackScrapper using pip:

.. code-block:: bash

   pip install MITREAttackScrapper

Usage
=====

Here’s a simple example of how to use MITREAttackScrapper:

.. code-block:: python

   from pprint import pprint
   from MITREAttackScrapper.techniques.enterprise import MITREAttackEnterpriseTechniques
   from MITREAttackScrapper.tactics.enterprise import MITREAttackEnterpriseTactics
   from MITREAttackScrapper.mitigations.enterprise import MITREAttackEnterpriseMitigations
   from MITREAttackScrapper.superclass import MITREAttackInformation

   def render(mitre: MITREAttackInformation) -> None:
       """
       Render the MITRE ATT&CK data.
       """
       data = mitre.get_list()
       target_id = data[0]["id"]
       pprint(mitre.get(target_id))

   if "__main__" == __name__:
       render(MITREAttackEnterpriseTechniques)
       render(MITREAttackEnterpriseTactics)
       render(MITREAttackEnterpriseMitigations)
       print("Done!")

Modules Overview
================

The MITREAttackScrapper package is organized into several modules:

- **cti**: Handles the scraping of CTI(Cyber Threat Intelligence) data.
- **mitigations**: Manages the retrieval of cyberthreat mitigation strategies against attacks techniques
- **tactics**: Extracts tactical information.
- **techniques**: Gathers data on various techniques.
- **utils**: Provides utility functions to support scraping and data handling.

For detailed information on each module, refer to the respective documentation pages.
