import json
import tkinter as tk
from tkinter import filedialog, messagebox

def merge_sboms(syft_file, dc_file, output_file="merged-sbom.json"):
    with open(syft_file, "r") as f:
        syft_sbom = json.load(f)
    with open(dc_file, "r") as f:
        dc_report = json.load(f)

    syft_components = syft_sbom.get("components", [])
    existing_names = {comp["name"].lower() for comp in syft_components}
    merged_components = syft_components[:]

    for dep in dc_report.get("dependencies", []):
        file_name = dep.get("fileName", "")
        if file_name.lower().endswith(".dll"):
            base_name = file_name.rsplit(".", 1)[0].lower()
            if base_name not in existing_names:
                new_component = {
                    "type": "library",
                    "name": base_name,
                    "version": "unknown",
                    "bom-ref": f"manual:{base_name}",
                    "properties": [
                        {
                            "name": "added-from",
                            "value": "dependency-check"
                        }
                    ]
                }
                merged_components.append(new_component)
                existing_names.add(base_name)

    syft_sbom["components"] = merged_components
    syft_sbom.setdefault("bomFormat", "CycloneDX")
    syft_sbom.setdefault("specVersion", "1.4")
    syft_sbom.setdefault("version", 1)

    with open(output_file, "w") as f:
        json.dump(syft_sbom, f, indent=2)

    messagebox.showinfo("Success", f"Merged SBOM saved as:\n{output_file}")

def select_files_and_merge():
    root = tk.Tk()
    root.withdraw()

    syft_file = filedialog.askopenfilename(title="Select Syft CycloneDX SBOM JSON",
                                           filetypes=[("JSON files", "*.json")])
    if not syft_file:
        messagebox.showwarning("Cancelled", "Syft file not selected.")
        return

    dc_file = filedialog.askopenfilename(title="Select Dependency-Check JSON Report",
                                         filetypes=[("JSON files", "*.json")])
    if not dc_file:
        messagebox.showwarning("Cancelled", "Dependency-Check file not selected.")
        return

    merge_sboms(syft_file, dc_file)

if __name__ == "__main__":
    select_files_and_merge()
  
