# CyberShield

CyberShield is a local DBMS prototype for correlating cybersecurity incidents, operational assets, vulnerabilities, indicators, MITRE ATT&CK techniques, and semi-structured threat intelligence.

## Phase 1: database setup

PostgreSQL is the relational system of record. MongoDB holds semi-structured threat intelligence. The scripts use only synthetic data.

1. Copy `.env.example` to `.env`, then set `POSTGRES_PASSWORD` and `MONGODB_URI`.
2. Run `./database/init.ps1`; it creates `cybershield_db` if it does not exist, then builds and verifies PostgreSQL.
4. From `backend`, run `npm install`, `npm run mongo:seed`, then `npm run mongo:verify`.
5. Run `psql $env:DATABASE_URL -v ON_ERROR_STOP=1 -f database/queries.sql` to exercise DBMS demonstration queries.

The relational design contains exactly 17 tables, including junction tables for the M:N relationships. `database/` contains schema, indexes, views, functions/procedure, trigger, seed, verification, and query demonstration scripts. The seeded demo incident is `incident_id = 1`, Phishing Attack Targeting Employee, tied to `LAPTOP-007`, an intentionally vulnerable browser entry, a repeated malicious indicator, the synthetic `Example Group`, and matching MongoDB intelligence.

## Phase 2: backend API

The Express API is in `backend/src`. It connects to PostgreSQL and MongoDB with `.env`, uses bcrypt password verification and 8-hour JWTs, and enforces role-based authorization. All seeded accounts use the synthetic demo password `password`; change it outside demo use.

Run `npm install` and `npm start` from `backend`. The API listens at `http://localhost:4000`; `GET /health` is unauthenticated. Login with `POST /api/auth/login`, then send the returned token as `Authorization: Bearer <token>`.

Implemented authenticated resources: `GET /api/users`, `GET /api/assets`, `GET /api/assets/:id`, `GET /api/software`, `GET /api/vulnerabilities`, `GET/POST /api/incidents`, `GET/PUT /api/incidents/:id`, `GET /api/incidents/:id/correlation`, `GET/POST /api/incidents/:id/responses`, `GET /api/indicators`, `GET /api/threat-intelligence/:indicator`, `GET /api/analytics/overview`, and `GET /api/audit-logs`.

All roles can read operational data. Admins, Security Analysts, and Incident Responders can create/update incidents and record response actions. Audit logs are restricted to Admins and Threat Researchers. The correlation endpoint combines PostgreSQL investigation data with MongoDB matches and evaluates repeated indicators, critical vulnerabilities, threat-intelligence matches, recurring assets, response gaps, and related incidents.

Run `npm run test:integration` from `backend` to test every endpoint against the live databases, including bcrypt login, RBAC rejection, MongoDB intelligence lookup, write paths, and all correlation rules.

## Phase 3: web preview

The React/Vite frontend is in `frontend`. With the backend running on port `4000`, run `npm install` and `npm run dev` from `frontend`, then open `http://127.0.0.1:5173`.

The demo opens on a polished login page and signs into the live analyst dashboard using `avery.shah@cybershield.test` with password `password`. The navigation includes the overview, incident queue, connected investigation, assets, vulnerabilities, MongoDB threat intelligence search, analytics, and audit logs. Select **Phishing Attack Targeting Employee** from the incident queue for the complete professor demo path.

## Phase 4: analyst assistance and graph

The incident investigation now includes a relationship graph driven by the live incident payload: incident to assets, indicators, MITRE techniques, MongoDB threat intelligence, and response actions. It also includes a deterministic NLP assistance panel. The `POST /api/nlp/analyze` endpoint suggests a category, severity, ATT&CK techniques, keywords, and syntactically visible indicators using explainable keyword rules; its results are explicitly advisory and must be confirmed or changed by an analyst.

## Deployment configuration

The target deployment uses Vercel for the frontend, Render for the backend, Neon for PostgreSQL, and MongoDB Atlas for MongoDB.

### Local development

1. Copy `.env.example` to `.env` without overwriting an existing `.env`.
2. For local PostgreSQL, set `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD`. Leave `DATABASE_URL` empty.
3. Set `MONGODB_URI` and `JWT_SECRET`.
4. Set `FRONTEND_URL=http://localhost:5173` or leave it unset; both `localhost:5173` and `127.0.0.1:5173` are allowed by default.
5. Initialize PostgreSQL with `./database/init.ps1` and seed MongoDB from `backend` with `npm run mongo:seed`.
6. Start the backend from `backend` with `npm start`.
7. Start the frontend from `frontend` with `npm run dev`.

The Vite development proxy sends `/api` requests to `http://localhost:4000`, so no frontend environment variable is required locally.

### Render backend

Create a Render Web Service with:

```text
Root directory: backend
Build command: npm install
Start command: npm start
```

Set these Render environment variables:

```text
DATABASE_URL=your-Neon-connection-string
MONGODB_URI=your-MongoDB-Atlas-connection-string
JWT_SECRET=your-long-random-secret
FRONTEND_URL=https://your-project.vercel.app
```

Render supplies `PORT` automatically. Do not configure `POSTGRES_*` when using `DATABASE_URL`; the backend prefers `DATABASE_URL` for Neon and falls back to the local `POSTGRES_*` variables when it is absent.

### Vercel frontend

Create a Vercel project with:

```text
Root directory: frontend
Build command: npm run build
Output directory: dist
```

Set this Vercel environment variable:

```text
VITE_API_URL=https://your-backend.onrender.com/api
```

`VITE_API_URL` contains only the public API URL. Never put database credentials, `JWT_SECRET`, or `MONGODB_URI` in a `VITE_` variable because Vite exposes those variables to browser code.

The backend accepts the configured Vercel origin plus the two local development origins. Do not set `FRONTEND_URL=*`; wildcard origins are rejected because the API uses credentialed CORS.

## Production security

The production login screen does not prefill demo credentials. Local Vite development keeps the synthetic demo values for the existing demonstration workflow; the seed scripts are manual and are not run by the Render build or start commands.

The backend applies login-only rate limiting, Helmet security headers without an API CSP, request validation for incident and response writes, and a `/ready` endpoint that checks PostgreSQL and MongoDB. Run `npm run test:security` from `backend` against the configured databases to verify these behaviors.
