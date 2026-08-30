# AttackPathX

AttackPathX is a simulated-enterprise attack path analysis platform. It never scans or exploits live systems. The FastAPI backend constructs a directed NetworkX graph and only traverses semantic movement edges: `NETWORK_ACCESS`, `EXPLOITS`, account/permission transitions, `ADMIN_ACCESS`, and `PRIVILEGE_ESCALATION`. Descriptive links are intentionally excluded.

## Run locally

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -r backend/requirements.txt
npm install
npm run dev
```

This starts the Vite frontend on `http://localhost:5173` and the FastAPI backend on `http://localhost:8000`. The frontend uses same-origin `/api/...` requests in production and the Vite proxy in development, so no hardcoded localhost URLs are needed in client code.

## Risk model

The score is a project-specific 0–100 prioritization aid, not an industry standard. It combines entry exposure, vulnerability severity/exploitability, privilege-gaining transitions, target criticality, and a penalty for edges marked as excessive permission. Bands are Informational (0–29), Low (30–49), Medium (50–74), High (75–89), and Critical (90–100).

`POST /api/environments/demo/analyze` discovers all cycle-free paths within a bounded depth, scores and ranks them, produces graph-derived explanations, and generates remediation recommendations. `POST /api/environments/demo/what-if` removes a node, relationship, or vulnerability from an in-memory copy before rerunning the same engine.

## Supabase

The migration contains authenticated user-owned environments and saved analysis tables with RLS. For production, initialise a Supabase project, apply `supabase/migrations/001_initial.sql`, configure the frontend variables in `.env.example`, and add a server-side Supabase client for persisting returned analysis runs after the frontend’s Supabase Auth session has been verified.
