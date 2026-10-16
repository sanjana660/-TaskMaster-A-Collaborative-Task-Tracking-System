import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { PrismaClient, TaskStatus, MemberRole } from '@prisma/client';
import { z, ZodError } from 'zod';

const prisma = new PrismaClient();
const app = express();
const port = Number(process.env.PORT ?? 3000);
const jwtSecret = process.env.JWT_SECRET ?? 'development-secret-change-me';
const uploadDir = path.resolve(process.env.UPLOAD_DIR ?? 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(uploadDir));

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 10 * 1024 * 1024 },
});

type AuthRequest = Request & { user?: { id: string; email: string } };
const revokedTokenIds = new Set<string>();
const notificationClients = new Map<string, Set<Response>>();

function publishNotification(userIds: string[], event: string, data: Record<string, unknown>) {
  const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const userId of new Set(userIds)) {
    for (const client of notificationClients.get(userId) ?? []) client.write(message);
  }
}

async function publishTeamNotification(teamId: string, event: string, data: Record<string, unknown>, extraUserIds: string[] = []) {
  const memberships = await prisma.membership.findMany({ where: { teamId }, select: { userId: true } });
  publishNotification([...memberships.map((membership) => membership.userId), ...extraUserIds], event, data);
}

function signToken(user: { id: string; email: string }) {
  return jwt.sign(user, jwtSecret, { expiresIn: '15m', jwtid: crypto.randomUUID() });
}

function auth(req: AuthRequest, res: Response, next: NextFunction) {
  const header = req.header('authorization');
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required' });
  try {
    const payload = jwt.verify(header.slice(7), jwtSecret) as jwt.JwtPayload & { id: string; email: string };
    if (!payload.jti || revokedTokenIds.has(payload.jti)) return res.status(401).json({ error: 'Token has been revoked' });
    req.user = { id: payload.id, email: payload.email };
    (req as AuthRequest & { tokenId?: string }).tokenId = payload.jti;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function requireTeamMember(userId: string, teamId: string) {
  const membership = await prisma.membership.findUnique({ where: { userId_teamId: { userId, teamId } } });
  if (!membership) throw Object.assign(new Error('Team membership required'), { status: 403 });
  return membership;
}

const registerSchema = z.object({ email: z.string().email(), password: z.string().min(8), name: z.string().trim().min(1).max(100) });
const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });
const taskSchema = z.object({ title: z.string().trim().min(1).max(200), description: z.string().max(10000).optional(), dueDate: z.coerce.date().optional(), teamId: z.string(), assigneeId: z.string().optional() });
const taskUpdateSchema = taskSchema.partial().extend({ status: z.nativeEnum(TaskStatus).optional() });

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/api/auth/register', async (req, res) => {
  const input = registerSchema.parse(req.body);
  const existing = await prisma.user.findUnique({ where: { email: input.email.toLowerCase() } });
  if (existing) return res.status(409).json({ error: 'Email is already registered' });
  const user = await prisma.user.create({ data: { email: input.email.toLowerCase(), name: input.name, passwordHash: await argon2.hash(input.password) }, select: { id: true, email: true, name: true, createdAt: true } });
  return res.status(201).json({ user, accessToken: signToken({ id: user.id, email: user.email }) });
});

app.post('/api/auth/login', async (req, res) => {
  const input = loginSchema.parse(req.body);
  const user = await prisma.user.findUnique({ where: { email: input.email.toLowerCase() } });
  if (!user || !(await argon2.verify(user.passwordHash, input.password))) return res.status(401).json({ error: 'Invalid credentials' });
  return res.json({ user: { id: user.id, email: user.email, name: user.name }, accessToken: signToken({ id: user.id, email: user.email }) });
});

app.post('/api/auth/logout', auth, (req: AuthRequest, res) => {
  const tokenId = (req as AuthRequest & { tokenId?: string }).tokenId;
  if (tokenId) revokedTokenIds.add(tokenId);
  return res.status(204).send();
});

app.get('/api/notifications/stream', (req: AuthRequest, res) => {
  const queryToken = z.string().optional().parse(req.query.token);
  const header = req.header('authorization');
  const rawToken = header?.startsWith('Bearer ') ? header.slice(7) : queryToken;
  if (!rawToken) return res.status(401).json({ error: 'Authentication required' });
  let user: { id: string; email: string };
  try {
    const payload = jwt.verify(rawToken, jwtSecret) as jwt.JwtPayload & { id: string; email: string };
    if (!payload.jti || revokedTokenIds.has(payload.jti)) return res.status(401).json({ error: 'Token has been revoked' });
    user = { id: payload.id, email: payload.email };
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.flushHeaders();
  res.write(`event: ready\ndata: ${JSON.stringify({ connected: true })}\n\n`);
  const clients = notificationClients.get(user.id) ?? new Set<Response>();
  clients.add(res);
  notificationClients.set(user.id, clients);
  const heartbeat = setInterval(() => res.write(': heartbeat\n\n'), 30000);
  req.on('close', () => { clearInterval(heartbeat); clients.delete(res); if (!clients.size) notificationClients.delete(user.id); });
});

app.get('/api/users/me', auth, async (req: AuthRequest, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user!.id }, select: { id: true, email: true, name: true, createdAt: true, memberships: { include: { team: true } } } });
  return res.json(user);
});

app.patch('/api/users/me', auth, async (req: AuthRequest, res) => {
  const input = z.object({ name: z.string().trim().min(1).max(100), email: z.string().email() }).partial().parse(req.body);
  const user = await prisma.user.update({ where: { id: req.user!.id }, data: input, select: { id: true, email: true, name: true, updatedAt: true } });
  return res.json(user);
});

app.post('/api/teams', auth, async (req: AuthRequest, res) => {
  const input = z.object({ name: z.string().trim().min(1).max(120), description: z.string().max(1000).optional() }).parse(req.body);
  const team = await prisma.team.create({ data: { ...input, memberships: { create: { userId: req.user!.id, role: MemberRole.OWNER } } }, include: { memberships: true } });
  return res.status(201).json(team);
});

app.post('/api/teams/:teamId/members', auth, async (req: AuthRequest, res) => {
  const teamId = z.string().parse(req.params.teamId);
  await requireTeamMember(req.user!.id, teamId);
  const input = z.object({ userId: z.string(), role: z.nativeEnum(MemberRole).default(MemberRole.MEMBER) }).parse(req.body);
  const membership = await prisma.membership.create({ data: { teamId, ...input } });
  return res.status(201).json(membership);
});

app.post('/api/teams/:teamId/invitations', auth, async (req: AuthRequest, res) => {
  const teamId = z.string().parse(req.params.teamId);
  const membership = await requireTeamMember(req.user!.id, teamId);
  if (membership.role !== MemberRole.OWNER) return res.status(403).json({ error: 'Only team owners can invite members' });
  const input = z.object({ email: z.string().email(), role: z.nativeEnum(MemberRole).default(MemberRole.MEMBER) }).parse(req.body);
  const token = crypto.randomBytes(32).toString('hex');
  const invitation = await prisma.invitation.create({ data: { email: input.email.toLowerCase(), role: input.role, teamId, inviterId: req.user!.id, tokenHash: crypto.createHash('sha256').update(token).digest('hex'), expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) }, select: { id: true, email: true, teamId: true, role: true, expiresAt: true } });
  return res.status(201).json({ invitation, token });
});

app.post('/api/team-invitations/:token/accept', auth, async (req: AuthRequest, res) => {
  const tokenHash = crypto.createHash('sha256').update(z.string().parse(req.params.token)).digest('hex');
  const invitation = await prisma.invitation.findUnique({ where: { tokenHash } });
  if (!invitation || invitation.status !== 'PENDING' || invitation.expiresAt < new Date()) return res.status(400).json({ error: 'Invitation is invalid or expired' });
  if (invitation.email !== req.user!.email.toLowerCase()) return res.status(403).json({ error: 'Invitation belongs to a different email address' });
  const membership = await prisma.membership.upsert({ where: { userId_teamId: { userId: req.user!.id, teamId: invitation.teamId } }, update: { role: invitation.role }, create: { userId: req.user!.id, teamId: invitation.teamId, role: invitation.role } });
  await prisma.invitation.update({ where: { id: invitation.id }, data: { status: 'ACCEPTED' } });
  return res.json(membership);
});

app.get('/api/tasks', auth, async (req: AuthRequest, res) => {
  const query = z.object({ teamId: z.string().optional(), status: z.nativeEnum(TaskStatus).optional(), assigneeId: z.string().optional(), search: z.string().optional(), sort: z.enum(['createdAt', 'dueDate', 'title']).default('createdAt'), order: z.enum(['asc', 'desc']).default('desc') }).parse(req.query);
  const memberships = await prisma.membership.findMany({ where: { userId: req.user!.id }, select: { teamId: true } });
  const teamIds = query.teamId ? [query.teamId] : memberships.map((membership) => membership.teamId);
  if (query.teamId) await requireTeamMember(req.user!.id, query.teamId);
  const tasks = await prisma.task.findMany({ where: { teamId: { in: teamIds }, status: query.status, assigneeId: query.assigneeId, OR: query.search ? [{ title: { contains: query.search, mode: 'insensitive' } }, { description: { contains: query.search, mode: 'insensitive' } }] : undefined }, include: { assignee: { select: { id: true, name: true, email: true } }, creator: { select: { id: true, name: true } }, _count: { select: { comments: true, attachments: true } } }, orderBy: { [query.sort]: query.order } });
  return res.json(tasks);
});

app.post('/api/tasks', auth, async (req: AuthRequest, res) => {
  const input = taskSchema.parse(req.body);
  await requireTeamMember(req.user!.id, input.teamId);
  if (input.assigneeId) await requireTeamMember(input.assigneeId, input.teamId);
  const task = await prisma.task.create({ data: { ...input, creatorId: req.user!.id }, include: { assignee: true } });
  await publishTeamNotification(input.teamId, 'task.created', { taskId: task.id, title: task.title, assigneeId: task.assigneeId });
  return res.status(201).json(task);
});

app.patch('/api/tasks/:taskId', auth, async (req: AuthRequest, res) => {
  const taskId = z.string().parse(req.params.taskId);
  const input = taskUpdateSchema.parse(req.body);
  const task = await prisma.task.findUnique({ where: { id: taskId } });
  if (!task) return res.status(404).json({ error: 'Task not found' });
  await requireTeamMember(req.user!.id, task.teamId);
  if (input.assigneeId) await requireTeamMember(input.assigneeId, task.teamId);
  const updatedTask = await prisma.task.update({ where: { id: taskId }, data: input, include: { assignee: true } });
  await publishTeamNotification(task.teamId, 'task.updated', { taskId: updatedTask.id, title: updatedTask.title, status: updatedTask.status, assigneeId: updatedTask.assigneeId });
  return res.json(updatedTask);
});

app.delete('/api/tasks/:taskId', auth, async (req: AuthRequest, res) => {
  const taskId = z.string().parse(req.params.taskId);
  const task = await prisma.task.findUnique({ where: { id: taskId } });
  if (!task) return res.status(404).json({ error: 'Task not found' });
  await requireTeamMember(req.user!.id, task.teamId);
  await prisma.task.delete({ where: { id: task.id } });
  return res.status(204).send();
});

app.post('/api/tasks/:taskId/comments', auth, async (req: AuthRequest, res) => {
  const input = z.object({ body: z.string().trim().min(1).max(5000) }).parse(req.body);
  const taskId = z.string().parse(req.params.taskId);
  const task = await prisma.task.findUnique({ where: { id: taskId } });
  if (!task) return res.status(404).json({ error: 'Task not found' });
  await requireTeamMember(req.user!.id, task.teamId);
  const comment = await prisma.comment.create({ data: { ...input, taskId: task.id, authorId: req.user!.id }, include: { author: { select: { id: true, name: true } } } });
  await publishTeamNotification(task.teamId, 'task.commented', { taskId: task.id, commentId: comment.id, authorId: req.user!.id });
  return res.status(201).json(comment);
});

app.post('/api/tasks/:taskId/attachments', auth, upload.single('file'), async (req: AuthRequest, res) => {
  const taskId = z.string().parse(req.params.taskId);
  const task = await prisma.task.findUnique({ where: { id: taskId } });
  if (!task) return res.status(404).json({ error: 'Task not found' });
  await requireTeamMember(req.user!.id, task.teamId);
  if (!req.file) return res.status(400).json({ error: 'A file is required' });
  const attachment = await prisma.attachment.create({ data: { filename: req.file.filename, originalName: req.file.originalname, mimeType: req.file.mimetype, path: `/uploads/${req.file.filename}`, taskId: task.id, uploaderId: req.user!.id } });
  await publishTeamNotification(task.teamId, 'task.attachment_added', { taskId: task.id, attachmentId: attachment.id, uploaderId: req.user!.id });
  return res.status(201).json(attachment);
});

app.post('/api/ai/task-description', auth, async (req: AuthRequest, res) => {
  const input = z.object({ title: z.string().trim().min(1).max(200), context: z.string().max(5000).optional() }).parse(req.body);
  const apiUrl = process.env.AI_API_URL;
  const apiKey = process.env.AI_API_KEY;
  const model = process.env.AI_MODEL ?? 'gpt-4o-mini';
  if (!apiUrl || !apiKey) return res.status(503).json({ error: 'AI integration is not configured' });
  const aiResponse = await fetch(apiUrl.replace(/\/$/, '') + '/chat/completions', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ model, temperature: 0.3, messages: [{ role: 'system', content: 'Write concise, actionable task descriptions. Return only the description.' }, { role: 'user', content: `Task title: ${input.title}\nAdditional context: ${input.context ?? 'None'}` }] }) });
  if (!aiResponse.ok) return res.status(502).json({ error: 'AI provider request failed' });
  const result = await aiResponse.json() as { choices?: Array<{ message?: { content?: string } }> };
  const description = result.choices?.[0]?.message?.content?.trim();
  if (!description) return res.status(502).json({ error: 'AI provider returned no description' });
  return res.json({ description, model });
});

app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (error instanceof ZodError) return res.status(400).json({ error: 'Validation failed', details: error.issues });
  if (error instanceof multer.MulterError) return res.status(400).json({ error: error.message });
  const status = typeof error === 'object' && error !== null && 'status' in error && typeof error.status === 'number' ? error.status : 500;
  console.error(error);
  return res.status(status).json({ error: status === 500 ? 'Internal server error' : (error as Error).message });
});

app.listen(port, () => console.log(`TaskMaster API listening on http://localhost:${port}`));

process.on('SIGTERM', async () => { await prisma.$disconnect(); process.exit(0); });
