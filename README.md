# ForensicSML (Stage 1: evidence management)

## Setup
**macOS / Linux**
```
cd forensic-sml
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```
**Windows (PowerShell)**
```
cd forensic-sml
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 in your browser. (Bootstrap loads from a CDN, so you need internet access.)

If PowerShell blocks activation: `Set-ExecutionPolicy -Scope Process RemoteSigned`.
If port 5000 is busy (macOS AirPlay), change `port=5000` in `app.py` to 5001.

## Try it
Evidence > upload `data/sample_evidence.csv` (or the template) > preview, validation report and SHA-256 hash.
The sample dataset is SYNTHETIC; regenerate it with `python data/generate_sample_data.py`.
