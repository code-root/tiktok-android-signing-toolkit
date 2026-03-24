# GitHub publish guide — `tiktok-android-signing-toolkit`

This document helps you publish this folder as a **standalone** public repository with a clear name, description, topics, and a first release.

**Arabic summary:** أنشئ مستودعًا فارغًا باسم مقترح، انسخ الوصف والتاقات من هذا الملف، ادفع من مجلد `tiktok_final` فقط، ثم أنشئ إصدارًا `v1.0.0` باستخدام `docs/RELEASE_NOTES_v1.0.0.md`.

---

## Suggested repository name

| Option | Rationale |
|--------|-----------|
| **`tiktok-android-signing-toolkit`** | Clear, searchable, describes signing + Android scope. **Recommended.** |
| `tiktok-v44-research-toolkit` | Emphasizes app version alignment. |

Use the same slug in URLs: `https://github.com/<your-username>/tiktok-android-signing-toolkit`

---

## About — short description (copy into GitHub)

**English (primary):**

> Research-oriented Python toolkit for TikTok Android v44.x: local signing (X-Gorgon, X-Argus, X-Ladon), device registration, login client, MITM helpers, tests — educational use only.

**Arabic (optional in README or release notes):**

> مجموعة بايثون للبحث والتعليم حول TikTok Android v44.x: توقيع محلي، تسجيل جهاز، لوجن، اختبارات — للاستخدام التعليمي فقط.

---

## Topics (tags) — add under Repository → ⚙️ Settings → General, or on the main repo page

Suggested GitHub topics (paste as comma-separated or one per line):

```
tiktok
android
reverse-engineering
python
api-security
signing
x-gorgon
mitm
device-registration
login-flow
research
pycryptodome
```

---

## First release — title & notes (copy into Releases → Draft new release)

- **Tag:** `v1.0.0`
- **Release title:** `v1.0.0 — Initial public release`

**Release description (body):**

```markdown
## Highlights
- **Signing:** Local `sign()` pipeline — X-Gorgon, X-Khronos, X-Argus, X-Ladon, X-SS-STUB (`ttk/signing_engine.py`).
- **Flows:** Device registration, multi-step login client, combined register+login (`ttk/device_register.py`, `ttk/login_client.py`, `ttk/flow.py`).
- **Research tools:** MITM Raw folder parsing, feed example, APK `sig_hash` helper (`ttk/mitm_raw.py`, `ttk/feed_api_client.py`, `ttk/tiktok_apk_sig.py`).
- **Quality:** Comprehensive tests (`tests/test_all.py`), fixtures under `fixtures/`, bilingual docs (`README.md`, `README.ar.md`).

## Requirements
- Python 3.10+
- See `requirements.txt`

## Legal
For research and education. Use may violate platform Terms of Service; you are responsible for compliance with applicable law.
```

---

## Push from this directory (new repo, not the parent monorepo)

From the machine that has this project:

```bash
cd /path/to/tiktok_final
git init
git branch -M main
git add -A
git status   # confirm no secrets (e.g. proxsy.txt, my_device.json are gitignored)
git commit -m "chore: initial public release v1.0.0"
```

Create an **empty** repository on GitHub (no README/license if you already have them locally), then:

```bash
git remote add origin https://github.com/<YOUR_USER>/tiktok-android-signing-toolkit.git
git push -u origin main
```

### Using GitHub CLI (`gh`)

```bash
gh repo create tiktok-android-signing-toolkit --public --source=. --remote=origin --push \
  --description "Research Python toolkit: TikTok Android v44.x signing, device_register, login, tests."
```

Then add topics in the web UI (CLI `gh repo edit` supports `--add-topic` per topic).

```bash
gh repo edit --add-topic tiktok --add-topic android --add-topic reverse-engineering --add-topic python
# repeat for other topics as needed
```

Create release:

```bash
gh release create v1.0.0 --title "v1.0.0 — Initial public release" --notes-file docs/RELEASE_NOTES_v1.0.0.md
```

---

## Suggested workflows (tech stack)

These match what GitHub recommends for a **Python** repository and are already in the tree:

| Workflow | File | Purpose |
|----------|------|---------|
| **Python application / CI** | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | `pip install -r requirements.txt`, then `python tests/test_all.py` on **Ubuntu**, matrix **Python 3.10–3.13**, `pip` cache. |
| **CodeQL analysis** | [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) | Security/static analysis for **Python** on push/PR to `main`, plus **weekly** schedule. |

**Optional (not added by default):** enable from **Actions → New workflow** if you need them later:

- **Pylint** — useful after you add a `pyproject.toml` / relaxed `.pylintrc` (this codebase is large for strict lint out of the box).
- **Publish Python Package** — only if you publish `ttk` to PyPI.
- **Dependency review** — mainly for PRs when you have a lockfile or many dependencies.

README badges for **Python CI** and **CodeQL** point at the live workflow runs on the published repo.

---

## README badges

Published repository: [github.com/code-root/tiktok-android-signing-toolkit](https://github.com/code-root/tiktok-android-signing-toolkit). CI and CodeQL status badges are in `README.md` / `README.ar.md`.
