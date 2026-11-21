#!/usr/bin/env node
// hunt-lab —— 白名单内的轻量侦察 + 安全模板检测。
// 设计前提：绝不访问白名单以外的任何主机；限速；只跑非侵入模板。
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'

const ROOT = path.resolve(import.meta.dirname, '..')
const CFG = JSON.parse(fs.readFileSync(path.join(ROOT, 'config', 'targets.json'), 'utf8'))
const NO_NUCLEI = process.argv.includes('--no-nuclei')
const GAP_MS = Math.ceil(1000 / (CFG.policy.maxRps || 0.5))
const ALLOWED = new Set(CFG.targets.filter((t) => t.authorized).map((t) => t.host))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const HEADERS_WANT = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
]

function assertAllowed (host) {
  if (!ALLOWED.has(host)) throw new Error('refuse: ' + host + ' 不在 config/targets.json 白名单里')
}

async function probe (t) {
  assertAllowed(t.host)
  const t0 = Date.now()
  const ac = new AbortController()
  const timer = setTimeout(() => ac.abort(), 15000)
  try {
    const res = await fetch(t.url, {
      signal: ac.signal,
      redirect: 'follow',
      headers: { 'user-agent': 'hunt-lab/1.0 (+https://github.com/123caiji/hunt-lab; authorized public test targets only)' },
    })
    const body = await res.text()
    const h = res.headers
    const title = (body.match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i) || [, ''])[1].replace(/\s+/g, ' ').trim()
    const missing = HEADERS_WANT.filter((k) => !h.get(k))
    const banner = []
    for (const k of ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']) {
      const v = h.get(k)
      if (v) banner.push(k + ': ' + v)
    }
    return { host: t.host, url: res.url, status: res.status, ms: Date.now() - t0, title, server: h.get('server') || null, missingHeaders: missing, banner, ok: true }
  } catch (e) {
    const cause = e.cause ? (e.cause.code || e.cause.message) : null
    return { host: t.host, url: t.url, ms: Date.now() - t0, ok: false, error: (e.name === 'AbortError' ? 'timeout 15s' : e.message) + (cause ? ' (' + cause + ')' : '') }
  } finally {
    clearTimeout(timer)
  }
}

function runNuclei (url) {
  const p = CFG.policy
  const args = [
    '-u', url,
    '-jsonl', '-silent', '-no-color',
    '-rl', '10', '-c', '3', '-bs', '10',
    '-severity', p.nucleiSeverity.join(','),
    '-tags', p.nucleiTags.join(','),
    '-etags', p.nucleiExcludeTags.join(','),
    '-timeout', '10', '-retries', '1',
  ]
  const parse = (out) => out.split('\n').filter(Boolean).map((l) => {
    try {
      const j = JSON.parse(l)
      return { template: j['template-id'], severity: j.info && j.info.severity, matched: j['matched-at'] }
    } catch { return { raw: l } }
  })
  try {
    return parse(execFileSync('nuclei', args, { encoding: 'utf8', timeout: 120000, maxBuffer: 32 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }))
  } catch (e) {
    if (e.code === 'ENOENT') return [{ note: 'nuclei 未安装，跳过模板检测' }]
    return parse((e.stdout || '').toString())
  }
}

const results = []
for (const t of CFG.targets) {
  if (!t.authorized) { console.log('skip(未授权) ' + t.host); continue }
  console.log('probe ' + t.url)
  results.push(await probe(t))
  await sleep(GAP_MS)
}

if (!NO_NUCLEI) {
  for (const r of results) {
    if (!r.ok || r.status >= 400) continue
    console.log('nuclei ' + r.url)
    r.nuclei = runNuclei(r.url)
    await sleep(GAP_MS)
  }
}

const stamp = new Date().toISOString()
const summary = {
  generatedAt: stamp,
  targets: results.length,
  reachable: results.filter((r) => r.ok).length,
  findings: results.reduce((n, r) => n + ((r.nuclei || []).filter((x) => x.template).length), 0),
  results,
}
fs.mkdirSync(path.join(ROOT, 'data'), { recursive: true })
fs.writeFileSync(path.join(ROOT, 'data', 'latest.json'), JSON.stringify(summary, null, 2) + '\n')

const md = ['# hunt-lab 巡检 ' + stamp.slice(0, 10), '', '- 目标 ' + summary.targets + ' 个，可达 ' + summary.reachable + ' 个，nuclei 命中 ' + summary.findings + ' 条', '']
for (const r of results) {
  md.push('## ' + r.host)
  if (!r.ok) { md.push('不可达：' + r.error); md.push(''); continue }
  md.push('- ' + r.url + ' → ' + r.status + '（' + r.ms + 'ms）')
  if (r.title) md.push('- 标题：' + r.title)
  if (r.server) md.push('- Server：' + r.server)
  if (r.banner.length) md.push('- 指纹：' + r.banner.join('；'))
  if (r.missingHeaders.length) md.push('- 缺安全头：' + r.missingHeaders.join(', '))
  const hits = (r.nuclei || []).filter((x) => x.template)
  if (hits.length) { md.push('- nuclei 命中：'); for (const x of hits) md.push('  - [' + x.severity + '] ' + x.template + ' @ ' + x.matched) }
  md.push('')
}
fs.mkdirSync(path.join(ROOT, 'reports'), { recursive: true })
fs.writeFileSync(path.join(ROOT, 'reports', stamp.slice(0, 10) + '.md'), md.join('\n'))

console.log('done: ' + summary.targets + ' targets, ' + summary.findings + ' findings -> data/latest.json')
