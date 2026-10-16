import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const baseUrl = 'http://localhost:3000';
const projectRoot = process.cwd();
const emailSuffix = Date.now();
const alice = { email: `alice-${emailSuffix}@example.com`, password: 'correct-horse-battery-staple', name: 'Alice' };
const bob = { email: `bob-${emailSuffix}@example.com`, password: 'correct-horse-battery-staple', name: 'Bob' };
let server;

function startServer() {
  server = spawn(process.execPath, [path.join(projectRoot, 'dist', 'server.js')], { cwd: projectRoot, stdio: ['ignore', 'pipe', 'pipe'], env: process.env });
  server.stdout.on('data', (chunk) => process.stdout.write(chunk));
  server.stderr.on('data', (chunk) => process.stderr.write(chunk));
  server.on('error', (error) => console.error('Unable to start API:', error));
  server.on('exit', (code) => { if (code !== null && code !== 0) console.error(`API exited with code ${code}`); });
}

async function waitForServer() {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('Server did not start');
}

async function request(route, options = {}) {
  const response = await fetch(`${baseUrl}${route}`, { ...options, headers: { 'content-type': 'application/json', ...(options.headers ?? {}) } });
  const body = response.status === 204 ? null : await response.json();
  return { response, body };
}

try {
  startServer();
  await waitForServer();

  let result = await request('/api/auth/register', { method: 'POST', body: JSON.stringify(alice) });
  assert.equal(result.response.status, 201);
  const aliceToken = result.body.accessToken;
  const aliceId = result.body.user.id;

  result = await request('/api/auth/register', { method: 'POST', body: JSON.stringify(bob) });
  assert.equal(result.response.status, 201);
  const bobId = result.body.user.id;

  result = await request('/api/auth/login', { method: 'POST', body: JSON.stringify(alice) });
  assert.equal(result.response.status, 200);
  const token = result.body.accessToken;
  const auth = { authorization: `Bearer ${token}` };

  result = await request('/api/users/me', { headers: auth });
  assert.equal(result.body.email, alice.email);
  result = await request('/api/users/me', { method: 'PATCH', headers: auth, body: JSON.stringify({ name: 'Alice Updated' }) });
  assert.equal(result.body.name, 'Alice Updated');

  result = await request('/api/teams', { method: 'POST', headers: auth, body: JSON.stringify({ name: 'Product Team' }) });
  assert.equal(result.response.status, 201);
  const teamId = result.body.id;

  result = await request(`/api/teams/${teamId}/invitations`, { method: 'POST', headers: auth, body: JSON.stringify({ email: bob.email }) });
  assert.equal(result.response.status, 201);
  const invitationToken = result.body.token;

  result = await request('/api/auth/login', { method: 'POST', body: JSON.stringify(bob) });
  const bobToken = result.body.accessToken;
  result = await request(`/api/team-invitations/${invitationToken}/accept`, { method: 'POST', headers: { authorization: `Bearer ${bobToken}` } });
  assert.equal(result.response.status, 200);

  result = await request('/api/tasks', { method: 'POST', headers: auth, body: JSON.stringify({ title: 'Prepare release', description: 'Searchable release task', dueDate: '2026-12-01', teamId, assigneeId: bobId }) });
  assert.equal(result.response.status, 201);
  const taskId = result.body.id;

  result = await request(`/api/tasks?teamId=${teamId}&assigneeId=${bobId}` , { headers: auth });
  assert.equal(result.body.length, 1);
  result = await request(`/api/tasks?teamId=${teamId}&status=OPEN&search=release`, { headers: auth });
  assert.equal(result.body.length, 1);

  result = await request(`/api/tasks/${taskId}`, { method: 'PATCH', headers: auth, body: JSON.stringify({ status: 'COMPLETED' }) });
  assert.equal(result.body.status, 'COMPLETED');

  result = await request(`/api/tasks/${taskId}/comments`, { method: 'POST', headers: auth, body: JSON.stringify({ body: 'Looks good.' }) });
  assert.equal(result.response.status, 201);

  const filePath = path.resolve('scripts', 'smoke-attachment.txt');
  await fs.writeFile(filePath, 'attachment test');
  const form = new FormData();
  form.append('file', new Blob(['attachment test'], { type: 'text/plain' }), 'smoke-attachment.txt');
  const uploadResponse = await fetch(`${baseUrl}/api/tasks/${taskId}/attachments`, { method: 'POST', headers: auth, body: form });
  assert.equal(uploadResponse.status, 201);
  await fs.unlink(filePath);

  result = await request('/api/auth/logout', { method: 'POST', headers: auth });
  assert.equal(result.response.status, 204);
  result = await request('/api/users/me', { headers: auth });
  assert.equal(result.response.status, 401);
  console.log('Stories 1-12 passed. Optional stories 13-14 are not enabled.');
} finally {
  server?.kill();
}
