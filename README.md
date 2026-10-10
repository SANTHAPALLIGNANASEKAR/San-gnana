# PhishGuard AI

A student-friendly multimodal phishing detection prototype.

## Features
- URL heuristic checks: HTTPS, suspicious hostname patterns, TLD, hostname entropy,
  lookalike brand domains, best-effort RDAP registration age, and redirect chain.
- Message analysis for urgency, credential requests, financial pressure, impersonation,
  and social-engineering language.
- Optional logo/screenshot comparison using perceptual hashes against local references.
- Risk fusion into SAFE (no strong indicators), SUSPICIOUS, or HIGH RISK.

## Requirements
- Python 3.10+
- Internet connection for RDAP and redirect checks (optional, best-effort)

## Run on Windows
1. Extract the ZIP.
2. Open the extracted `PhishGuard_AI` folder in VS Code.
3. Open a terminal in that folder.
4. Run:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   python -m streamlit run app.py
   ```

5. Open the local URL printed by Streamlit, normally `http://localhost:8501`.

Automated heuristic tests (no live phishing sites):

```powershell
python -m pytest
```

If PowerShell blocks activation, you can run `.venv\Scripts\python.exe -m pip install -r requirements.txt`
and `.venv\Scripts\python.exe -m streamlit run app.py` without activating the environment.

## Logo matching
Put reference images that you are authorized to use in `trusted_brands/`, for example:
- `trusted_brands/google.png`
- `trusted_brands/microsoft.png`
- `trusted_brands/amazon.png`

No reference images are bundled. The app will explain this if the folder is empty.

## Important limitations
- This is a heuristic prototype, not a trained AI model and not a calibrated probability.
- Domain age and redirects may fail due to network conditions, server behavior, or unavailable RDAP data.
- Similarity heuristics can create false positives and false negatives.
- Image hashing compares broad visual structure; it does not prove brand authenticity.
- A low score does not prove a URL or message is safe.
- Do not use with real passwords, OTPs, private keys, or other secrets.
- Network requests can contact submitted domains. Only analyze URLs you are authorized to test.
- For production use, add robust SSRF protections, rate limits, dataset evaluation, trained models,
  safe sandboxing, privacy controls, and logging safeguards.
