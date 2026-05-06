# S.A.F.E. – Scam Analysis & Filtering Engine

**Final Year Project · University of Roehampton**  
**Author:** Anjali Karki Chhetri

---

## What this project is

**S.A.F.E.** (**S**cam **A**nalysis & **F**iltering **E**ngine) is a small **web prototype** that helps people **check suspicious messages** (SMS, WhatsApp, email, social media) before they click links, send money, or share codes.

- It gives a **rule-based risk score** (0–100), a **risk band** (Low / Medium / High / Critical), and a **likely scam category**.
- It explains **why** the message looks risky, using **plain language** and optional **technical detail** on the result page.
- It is built for **clarity and accessibility**, including older or non-technical users.

This repository’s **running application** is a **heuristic (rule-based) prototype**. It does **not** use machine learning, an NLP model, a database, user login, or external live APIs in the current code.

---

## Key features (current prototype)

| Feature | Description |
|--------|-------------|
| Message analysis | Paste text; the engine scores it using keyword and pattern rules in `prototype/app.py`. |
| Explainable output | Warning signs, matched indicators (advanced view), and highlighted phrases in the message. |
| Dataset & examples | The **Dataset** page (`/dataset`) lists realistic **scam** and **safe** examples and simple “real vs fake” comparisons for testing and learning. |
| About | The **About** page (`/about`) describes goals, limitations, and **future ideas** (clearly marked as not implemented). |

---

## Technology stack

- **Python** · **Flask** (server and routes)  
- **HTML** · **Jinja** (templates)  
- **CSS** (layout and styling; no React, no heavy JavaScript)

---

## How to run locally

1. Open a terminal and go to the prototype folder:

   ```bash
   cd prototype
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

   On Windows, if the `python` command is not found, use the **Python Launcher**:

   ```bash
   py -3.14 -m pip install -r requirements.txt
   ```

3. Start the app:

   ```bash
   python app.py
   ```

   Or:

   ```bash
   py -3.14 app.py
   ```

4. In a browser, open **http://127.0.0.1:5000/**

**Routes:**

| URL | Method | Purpose |
|-----|--------|---------|
| `/` | GET | Home – paste a message and submit |
| `/analyse` | POST | Runs analysis and shows the result page |
| `/dataset` | GET | Scam/safe examples and testing notes |
| `/about` | GET | Project description, limitations, future work |

---

## Current approach

The engine **does not “understand” language like a human**. It **adds points** when it finds indicators such as:

- **Urgency** (“act now”, “within 24 hours”, …)  
- **Suspicious links** (e.g. `http://`, odd domains, shorteners)  
- **Impersonation** (names of banks, HMRC, delivery firms, etc., as text cues)  
- **Money / investment** language  
- **OTP / password / verification** requests  
- **Emotional pressure** (emergency stories, “new number”, …)  
- **Unrealistic offers** (“guaranteed profit”, …)

The **total score** is **capped at 100** and mapped to a **risk band**. A **category** is chosen from keyword groups with the strongest match, with fallbacks such as **Likely Safe** or **Unknown/Suspicious** when signals are weak or mixed.

You can walk through the logic in **`prototype/app.py`** (comments are included to explain the scoring flow clearly).

---

## Dataset / testing page

The website includes a **Dataset** page with:

- **Labelled-style scam examples** (fake job, bank/OTP, parcel, HMRC, crypto, family emergency, subscription, SIM swap, wrong number, compensation) with **example text**, **expected category**, **expected risk**, and **main warning signs**.  
- **Safe examples** (meeting reminder, appointment, normal delivery wording, statement reminder without suspicious links, family chat).  
- **Common scam patterns** and **real vs fake** comparison cards.

These examples are **for education and manual testing**, not a stored database of user messages.

---

## Limitations

- **Prototype only** — not audited for production security or scale.  
- **Rule-based** — can miss novel scams or occasionally over-flag benign text.  
- **Not legal or financial advice** — always use **official apps, websites, or phone numbers** you look up yourself, and contact **Action Fraud** or your bank when something is wrong.  
- **No persistence** of pasted messages in this build (analysis in memory for the request).

---

## Future improvements (not in this codebase)

Ideas for a later version might include: ML/NLP models, a curated labelled dataset, OCR for screenshots, richer accessibility (e.g. audio), optional accounts with saved history, and integrations with trusted alert feeds. **None of these are required to run or explain the current prototype.**

---

## Repository layout (high level)

| Path | Role |
|------|------|
| `prototype/app.py` | Flask app and rule-based `analyse_message` logic |
| `prototype/templates/` | `index.html`, `result.html`, `dataset.html`, `about.html`, `partials/` |
| `prototype/static/style.css` | Styling |
| `docs/`, `diagrams/`, `appendix/` | Design and coursework artefacts (as in your module hand-in) |

---

## Licence / ethics

Coursework ethics and data-handling plans should follow your university’s process. This prototype is intended for **awareness and demonstration**, not for collecting real victims’ messages at scale.
