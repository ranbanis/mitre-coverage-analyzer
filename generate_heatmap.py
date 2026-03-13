import pandas as pd
import json
from datetime import datetime

# Configuration for the Navigator Layer
LAYER_NAME = "SIEM Detection Coverage Heatmap"
LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "4.9.1"
DOMAIN = "enterprise-attack"

def generate_navigator_layer(technique_counts):
    """Generates the JSON structure required by MITRE ATT&CK Navigator."""
    
    techniques_list = []
    
    for technique_id, count in technique_counts.items():
        # Define coloring logic based on the number of rules covering the technique
        if count == 0:
            color = "#ff6666" # Red (Gap)
        elif count <= 2:
            color = "#ffcc00" # Yellow (Basic Coverage)
        else:
            color = "#8ec843" # Green (Robust Coverage)
            
        techniques_list.append({
            "techniqueID": technique_id,
            "color": color,
            "score": int(count),
            "comment": f"Coverage: {count} deployed rule(s)."
        })

    # Base Navigator JSON skeleton
    layer_json = {
        "name": LAYER_NAME,
        "versions": {
            "attack": "14",
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION
        },
        "domain": DOMAIN,
        "description": "Auto-generated coverage heatmap based on SIEM rule inventory.",
        "filters": {
            "platforms": ["Windows", "Linux", "macOS", "Network", "Cloud"]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False
        },
        "hideDisabled": False,
        "techniques": techniques_list,
        "gradient": {
            "colors": ["#ff6666", "#ffcc00", "#8ec843"],
            "minValue": 0,
            "maxValue": 5
        }
    }
    
    return layer_json

def main():
    print("[*] Loading SIEM rule inventory...")
    try:
        # Load the exported rules from the SIEM
        df = pd.read_csv('rules_inventory.csv')
    except FileNotFoundError:
        print("[-] Error: rules_inventory.csv not found.")
        return

    # Ensure the required column exists
    if 'Technique_ID' not in df.columns:
        print("[-] Error: CSV must contain a 'Technique_ID' column (e.g., T1003).")
        return

    print("[*] Calculating technique coverage...")
    # Drop empty rows and count occurrences of each technique
    cleaned_techniques = df['Technique_ID'].dropna()
    coverage_counts = cleaned_techniques.value_counts().to_dict()

    print("[*] Generating MITRE ATT&CK Navigator JSON layer...")
    layer_data = generate_navigator_layer(coverage_counts)

    # Output the file
    output_filename = "attack_navigator_layer.json"
    with open(output_filename, 'w') as f:
        json.dump(layer_data, f, indent=4)
        
    print(f"[+] Success! Heatmap layer generated: {output_filename}")
    print("[*] Next Step: Upload this file to https://mitre-attack.github.io/attack-navigator/")

if __name__ == "__main__":
    main()
