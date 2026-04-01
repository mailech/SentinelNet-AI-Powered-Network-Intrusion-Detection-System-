import json
import os

folder = r"c:\Users\DELL\Downloads\infosys project"
for f in os.listdir(folder):
    if f.endswith('.ipynb'):
        path = os.path.join(folder, f)
        print(f"\n--- {f} ---")
        try:
            with open(path, 'r', encoding='utf-8') as f_in:
                data = json.load(f_in)
                cells = data.get('cells', [])
                for idx, cell in enumerate(cells[:5]):
                    c_type = cell.get('cell_type', 'unknown')
                    source = "".join(cell.get('source', []))[:150].replace('\n', ' ')
                    print(f"[{idx}] {c_type.upper()}: {source}")
                print(f"Total cells: {len(cells)}")
        except Exception as e:
            print(f"Error reading {f}: {e}")
