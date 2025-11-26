# BinTopsy

<p align="center">
  <img src="assets/logo.png" alt="BinTopsy Logo" width="400"/>
</p>

**BinTopsy** (Binary Autopsy) is a collection of lightweight, effective Python scripts designed to assist in the initial stages of static malware analysis and reverse engineering. 

These tools allow analysts to visualize file entropy, disassemble code snippets on the fly, scan binaries with YARA rules (supporting large dumps via pagination), and automate threat intelligence lookups via VirusTotal.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)


## Tools Included

### 1. Entropy Visualizer (`entropy-viz.py`)
Generates a 2D Shannon Entropy Heatmap of a binary file.
* **Use case:** Quickly identify packed sections, encrypted data, or compressed resources within a malware sample.
* **Features:** Customizable window size, high-resolution output.

### 2. Capstone Disassembler (`disasm.py`)
A CLI-based disassembler powered by the Capstone Engine.
* **Use case:** Quickly analyze shellcode or mixed hex/ASCII strings without opening a heavy debugger.
* **Features:** Supports multiple architectures (x86, x64, ARM, MIPS), handles "dirty" input (mixed hex/text), and file loading.

### 3. Chunk-Based YARA Scanner (`yara-chunk-scanner.py`)
A robust scanner that divides files into pages (chunks) to apply YARA rules.
* **Use case:** Scanning massive memory dumps or raw disk images where loading the whole file into RAM is impossible.
* **Features:** Recursive directory scanning, smart rule compilation, custom page sizes, and match offset calculation.

### 4. VirusTotal Folder Scanner (`vt-folder-scan.py`)
A privacy-aware directory scanner that checks file hashes against the VirusTotal API.
* **Use case:** Triage a folder of suspicious files to see what is already known to the community.
* **Features:** **Does not upload files** (hash only), respects API rate limits (Free/Premium modes), and supports exclusion filters (e.g., ignore `.jpg`).

---

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/BinTopsy.git](https://github.com/reverseame/BinTopsy.git)
    cd BinTopsy
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

### Configuration
To use the `vt-folder-scan.py`, you need a VirusTotal API Key.
1.  Create a file named `secrets.env` in the root directory.
2.  Add your key:
    ```env
    VT_API_KEY=your_64_character_api_key_here
    ```

---

## Usage Examples & Scenarios

### 1. Entropy Visualization (`entropy-viz.py`)

**Scenario A: Quick overview of a packed executable**

Standard scan with a default 4KB window.
```bash
python entropy-viz.py samples/malware.exe -o overview.png
```

**Scenario B: High-Resolution Analysis (Shellcode/Steganography)**
 Use a smaller window size (e.g., 256 bytes) to detect small, high-entropy payloads hidden inside legitimate files.

```bash
python entropy-viz.py suspicious_image.png -w 256 -o high_res_map.png
```

### 2. Capstone Disassembler (`disasm.py`)

**Scenario A: Analyzing Shellcode from a Hex Dump**

You found a suspicious string in a log file. Disassemble it immediately without saving it to a file.

```bash
python disasm.py -s "55 48 89 e5 48 83 ec 20" -a x64
```
**Scenario B: IoT Firmware Analysis (MIPS/ARM)**

Disassembling a header from a router firmware, specifying the base memory address (e.g., 0x80001000) to ensure relative jumps are calculated correctly.

```bash
python disasm.py -f firmware_bootloader.bin -a mips --base 0x80001000
```

### 3. Chunk-Based YARA Scanner (`yara-chunk-scanner.py`)

**Scenario A: Scanning a Memory Dump**

Scanning a large 8GB RAM dump. The tool reads it in 4MB chunks to keep memory usage low.

```bash
python yara-chunk-scanner.py memory_dump.raw ./rules/malware.yar -p 4194304
```

**Scenario B: Bulk Directory Scanning**

Recursively scan an entire folder of extracted files against a directory of YARA rules.

```bash
python yara-chunk-scanner.py ./extracted_files/ ./rules_repo/ -p 4096
```

### 4. VirusTotal Folder Scanner (`vt-folder-scan.py`)

**Scenario A: Triage a "Downloads" folder**

Check everything in the downloads folder, but ignore common media files (.jpg, .mp4) and logs to save API quota.

```bash
python vt-folder-scan.py ~/Downloads --avoid .jpg .jpeg .png .mp4 .log .txt
```

**Scenario B: Enterprise/Premium Scanning**

If you have a paid VirusTotal key, use the `--premium` flag to disable the 15-second rate limiter for faster processing.

```bash
python vt-folder-scan.py ./incident_response_data --premium
```

TODO

---

## Methodology & Reference

The underlying methodology used in **BinTopsy** is detailed in the following research paper. 

If you use this toolkit in your research or professional work, please cite:

> **Toward Structured Memory Forensics: A MITRE ATT&CK-Aligned Workflow for Malware Investigation** (Ricardo J. Rodríguez)
> **Published in:** 16th International Conference on Digital Forensics & Cyber Crime (ICDF2C 2025)
> **DOI/Link:** [TBA](https://doi.org/) /  [web repository](https://webdiis.unizar.es/~ricardo/files/papers/Rodriguez-ICDF2C-25.pdf)

#### BibTeX
```bibtex
@InProceedings{Rodriguez-ICDF2C-25,
  author    = {Ricardo J. Rodríguez},
  booktitle = {Proceedings of the 16th EAI International Conference on Digital Forensics & Cyber Crime},
  title     = {{Toward Structured Memory Forensics: A MITRE ATT\&CK-Aligned Workflow for Malware Investigation}},
  year      = {2025},
  note      = {Accepted for publication. To appear.},
  number    = {PP},
  pages     = {PP},
  publisher = {Springer},
  volume    = {PP},
  abstract  = {Memory forensics is emerging as an essential technique for detecting malware-related volatile indicators of compromise (IoCs) that traditional disk analysis may miss. However, the lack of standardized best practices for analyzing memory-resident malware evidence continues to limit the effectiveness and reproducibility of forensic investigations. In this work, we propose a structured five-phase workflow that formalizes best practices for the extraction and analysis of malware-related IoCs, from initial evidence preservation to binary program investigation. Our methodology is explicitly aligned with the MITRE ATT\&CK framework, allowing analysts to correlate volatile memory artifacts with known adversarial tactics and techniques. Additionally, we examine technical challenges (such as paging, on-demand paging, memory inconsistencies, and runtime binary transformations) that threaten the integrity and reliability of memory evidence. We further propose practical recommendations and outline future research directions for addressing these challenges, with the goal of improving the reliability, consistency, and forensic robustness of memory-based malware analysis.},
  keywords  = {digital forensics, memory forensics, methodology, indicators of compromise, malware analysis},
  url       = {https://webdiis.unizar.es/~ricardo/files/papers/Rodriguez-ICDF2C-25.pdf},
}
```
---

## AI Transparency & Credits

This repository is an example of **human-AI collaboration**.

* **Code:** The Python scripts were drafted by **Google Gemini**, then rigorously reviewed, refactored, and tested by **R. J. Rodríguez** to ensure accuracy and safety.
* **Visual Assets:** The **BinTopsy** logo was designed and generated by **Google Gemini**'s image generation capabilities.
* **Architecture & Methodology:** The tool selection, scanning logic, and research methodology were defined by **R. J. Rodríguez**.

*Disclaimer: While AI was used to accelerate the development process, every line of code has been manually audited by the author. The resulting tools represent a verified implementation of the concepts described in the methodology.*

---

## Funding support

Part of this research was supported by the Spanish National Cybersecurity Institute (INCIBE) under *Proyecto Estratégico de Ciberseguridad -- CIBERSEGURIDAD EINA UNIZAR* and by the Recovery, Transformation and Resilience Plan funds, financed by the European Union (Next Generation).

![INCIBE_logos](assets/INCIBE_logos.jpg)