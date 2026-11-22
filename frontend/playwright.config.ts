import { defineConfig } from '@playwright/test'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { randomBytes } from 'node:crypto'

const root = resolve(import.meta.dirname, '..')
const tmp = mkdtempSync(join(tmpdir(), 'netscope-e2e-'))
const python = process.platform === 'win32' ? '.\\.venv\\Scripts\\python.exe' : '.venv/bin/python'
process.env.NETSCOPE_E2E_KEY ||= randomBytes(20).toString('hex')

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  workers: 1,
  use: {baseURL: 'http://127.0.0.1:18765', viewport: {width: 1440, height: 900}},
  webServer: [
    {command: python + ' -m uvicorn netscope.main:app --host 127.0.0.1 --port 18765 --no-access-log',
      cwd: root, url: 'http://127.0.0.1:18765/', timeout: 45_000, env: {NETSCOPE_DB: join(tmp, 'test.db')}},
    {command: python + ' -m netscope.peer --port 18766', cwd: root, port: 18766,
      env: {NETSCOPE_PEER_TOKEN: process.env.NETSCOPE_E2E_KEY}},
  ],
})
