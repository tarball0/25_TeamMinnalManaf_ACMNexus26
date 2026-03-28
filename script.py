import os
import math
import numpy as np
from PIL import Image
import shutil

# Where to look for safe files (Windows default)
SEARCH_DIRS = ['C:\\Program Files', 'C:\\Program Files (x86)']
OUTPUT_DIR = './Benign_Images'
MAX_FILES = 3000 # Grab enough to balance against the malware dataset

def gather_benign_files():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    count = 0
    
    print(f"Scanning for safe executables. This might take a minute...")
    for search_dir in SEARCH_DIRS:
        for root, _, files in os.walk(search_dir):
            for file in files:
                if file.lower().endswith(('.exe', '.dll')):
                    if count >= MAX_FILES:
                        print(f"Successfully gathered {MAX_FILES} benign images!")
                        return
                    
                    filepath = os.path.join(root, file)
                    outpath = os.path.join(OUTPUT_DIR, f"benign_{count}.png")
                    
                    try:
                        # Convert to grayscale image
                        with open(filepath, 'rb') as f: data = f.read()
                        if not data: continue
                        
                        arr = np.frombuffer(data, dtype=np.uint8)
                        side = int(math.ceil(math.sqrt(len(arr))))
                        padded = np.pad(arr, (0, side*side - len(arr)), mode='constant')
                        Image.fromarray(padded.reshape((side, side)), 'L').save(outpath)
                        
                        count += 1
                        if count % 500 == 0: print(f"Converted {count} files...")
                    except Exception:
                        pass # Ignore files with permission errors

gather_benign_files()