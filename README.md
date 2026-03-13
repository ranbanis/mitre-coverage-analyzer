# MITRE ATT&CK Coverage Gap Analyzer

A Python utility that ingests an organization's SIEM detection rule inventory, aggregates coverage by MITRE ATT&CK technique, and automatically generates a dynamic heatmap layer for the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

## Overview
Understanding detection posture requires more than just counting rules. This tool allows security teams to:
* **Identify Blind Spots:** Instantly visualize which techniques have zero coverage (colored red).
* **Assess Depth:** Differentiate between shallow coverage (1 rule, colored yellow) and robust coverage (3+ rules, colored green).
* **Prioritize Engineering:** Drive the detection engineering lifecycle by focusing on high-prevalence, unmitigated techniques.

## Setup and Usage
1. Clone the repository: `git clone https://github.com/yourusername/mitre-coverage-analyzer.git`
2. Install dependencies: `pip install -r requirements.txt` (Only requires `pandas`)
3. Export your SIEM rules to a CSV named `rules_inventory.csv` (requires at least a `Technique_ID` column).
4. Run the analyzer: `python generate_heatmap.py`
5. Upload the resulting `attack_navigator_layer.json` to the online MITRE ATT&CK Navigator.
