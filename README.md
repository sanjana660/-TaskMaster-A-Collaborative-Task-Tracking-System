# TaskMaster API

A REST backend for collaborative task tracking with teams, assignments, comments, and attachments.

## Stack

- Node.js, Express 5, TypeScript
- PostgreSQL with Prisma ORM
- Argon2 password hashing and JWT access tokens
- Zod request validation

## Run locally

1. Install PostgreSQL and create a database named `taskmaster`.
2. Copy `.env.example` to `.env` and set `DATABASE_URL` and a strong `JWT_SECRET`.
3. Install dependencies and generate the Prisma client:

```bash
npm install
npm run db:generate
npm run db:migrate -- --name init
```

The workspace includes a local `.env` with the default PostgreSQL password `postgres`. If your PostgreSQL service uses a different password, update the password portion of `DATABASE_URL` before running the migration. The migration cannot be applied until those credentials match.

4. Start the API:

```bash
npm run dev
```

The server listens on `http://localhost:3000`.

## Endpoints

- `GET /health`
- `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`
- `GET/PATCH /api/users/me`
- `POST /api/teams`, `POST /api/teams/:teamId/members`
- `POST /api/teams/:teamId/invitations`, `POST /api/team-invitations/:token/accept`
- `GET/POST /api/tasks`
- `PATCH/DELETE /api/tasks/:taskId`
- `POST /api/tasks/:taskId/comments`
- `POST /api/tasks/:taskId/attachments` using multipart field `file`
- `GET /api/notifications/stream?token=<accessToken>` for Server-Sent Events
- `POST /api/ai/task-description` with `{ "title": "...", "context": "..." }`

Use `Authorization: Bearer <accessToken>` for protected endpoints. Task list supports `teamId`, `status`, `assigneeId`, `search`, `sort`, and `order` query parameters.

## User-story smoke test

After applying the migration, run `npm run test:stories`. This exercises registration, login, profile updates, team invitations, task creation and assignment, filtering, search, completion, comments, attachments, and logout token revocation.

The notification stream emits `task.created`, `task.updated`, `task.commented`, and `task.attachment_added` events to authenticated team members. The AI endpoint uses any OpenAI-compatible chat-completions provider configured through `AI_API_URL`, `AI_API_KEY`, and `AI_MODEL`; without those variables it returns `503` and the rest of the API remains available.

## Production notes

Use a strong secret from a secret manager, put uploads in object storage, add a reverse proxy with TLS, replace the in-memory revoked-token set with a persistent denylist or refresh-token rotation, and use a managed AI provider with request quotas before production deployment.
