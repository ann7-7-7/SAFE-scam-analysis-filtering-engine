S.A.F.E. – Scam Analysis & Filtering Engine (Prototype)
=======================================================

This directory contains a **minimal Flask proof-of-concept web UI** for
the S.A.F.E. (Scam Analysis & Filtering Engine) project.

The prototype:

- Accepts suspicious messages (SMS, WhatsApp, Email)
- Applies simple heuristic scam checks (no ML yet)
- Highlights risky words and links
- Shows a risk score and safety guidance
- Includes an `Evaluation` page to show current benchmark accuracy


Quick start
-----------

All commands below assume you are in the project root:

```bash
cd prototype
```

### 1. Create and activate a virtual environment

On **Windows (PowerShell)**:

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1
```

On **Windows (Command Prompt)**:

```bash
python -m venv .venv
.venv\Scripts\activate.bat
```

On **macOS / Linux** (if you run this outside Windows):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

With the virtual environment active:

```bash
pip install -r requirements.txt
```

### 3. Run the Flask app

From the `prototype` directory with the virtual environment active:

```bash
set FLASK_APP=app.py        # PowerShell: $env:FLASK_APP = "app.py"
set FLASK_ENV=development   # PowerShell: $env:FLASK_ENV = "development"
flask run
```

On PowerShell, the equivalent is:

```powershell
$env:FLASK_APP = "app.py"
$env:FLASK_ENV = "development"
flask run
```

### 4. Open in the browser

After `flask run` starts, open:

`http://127.0.0.1:5000`

You can also open:

- `http://127.0.0.1:5000/evaluation` to see benchmark accuracy and per-case results


Privacy notes
-------------

- Messages are **processed only in memory**.
- The app **does not write the raw message to disk**.
- The server logs only minimal metadata for debugging and evaluation:
  - timestamp (UTC ISO8601)
  - latency in milliseconds
  - risk band (Low / Medium / High)
  - channel (SMS / WhatsApp / Email)


Limitations
-----------

- This is a **prototype** – rules are intentionally simple and
  deterministic, with **no machine learning**.
- A **low** risk score does **not** guarantee safety; always treat
  unexpected messages with caution.

