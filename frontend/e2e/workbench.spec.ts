import { expect, test, type Page } from '@playwright/test'

const password = 'local-browser-test-password'
// The server uses a fresh database per run, shared by replacement workers.
const admin = 'operator-e2e'
// Ethernet/IPv4 TCP + UDP; RFC documentation addresses, both stamped 1700000000 UTC.
const syntheticCapture = Buffer.from('1MOyoQIABAAAAAAAAAAAAP//AAABAAAAAPFTZQAAAAA2AAAANgAAAAIAAAAAAgIAAAAAAQgARQAAKAABAABABo59wAACCsYzZBSoygG7AAAAAAAAAABQAiAA+QoAAADxU2UAAAAAKgAAACoAAAACAAAAAAICAAAAAAEIAEUAABwAAQAAQBGOfsAAAgrGM2QUqMsU6QAIVdc=', 'base64')

async function session(page: Page) {
  const setup = await page.request.get('/api/auth/setup')
  const {needs_initial_account} = await setup.json() as {needs_initial_account: boolean}
  const response = await page.request.post('/api/auth/' + (needs_initial_account ? 'register' : 'login'), {
    data: {username: admin, password},
  })
  expect(response.status()).toBe(needs_initial_account ? 201 : 200)
  await page.goto('/')
  await expect(page.getByRole('heading', {name: '网络总览', exact: true})).toBeVisible()
}

test('register, sign out and sign back in through the browser', async ({page}) => {
  await page.goto('/')
  const setup = await page.request.get('/api/auth/setup')
  const {needs_initial_account} = await setup.json() as {needs_initial_account: boolean}
  if (needs_initial_account) await page.getByRole('button', {name: '创建账户'}).click()
  await page.getByLabel('用户名', {exact: true}).fill(admin)
  await page.getByLabel('密码', {exact: true}).fill(password)
  await page.getByRole('button', {name: needs_initial_account ? '注册并登录' : '登录', exact: true}).click()
  await expect(page.getByRole('heading', {name: '网络总览', exact: true})).toBeVisible()
  await page.goto('/#settings')
  await page.getByRole('button', {name: '退出登录'}).click()
  await page.getByLabel('用户名', {exact: true}).fill(admin)
  await page.getByLabel('密码', {exact: true}).fill(password)
  await page.getByRole('button', {name: '登录', exact: true}).click()
  await expect.poll(async () => (await page.request.get('/api/auth/me')).status()).toBe(200)
})

test('import a synthetic PCAP, filter UDP and inspect its network and transport headers', async ({page}) => {
  await session(page)
  await page.goto('/#packets')
  // Scapy-generated Ethernet/IPv4 TCP + UDP fixture, containing only documentation addresses.
  await page.locator('input[type=file]').setInputFiles({name: 'synthetic.pcap', mimeType: 'application/octet-stream', buffer: syntheticCapture})
  await expect(page.getByRole('button', {name: '查看报文 1'})).toBeVisible()
  await page.getByLabel('协议层').selectOption('UDP')
  await page.getByRole('button', {name: '筛选', exact: true}).click()
  await expect(page.getByRole('button', {name: '查看报文 1'})).toHaveCount(0)
  await page.getByRole('button', {name: '查看报文 2'}).click()
  await expect(page.getByText('IPv4 首部', {exact: true})).toBeVisible()
  await expect(page.getByText('UDP 首部', {exact: true})).toBeVisible()
  await expect(page.getByText('5353', {exact: true})).toBeVisible()
})

test('measure a paired peer and read the recorded result', async ({page}) => {
  await session(page)
  await page.goto('/#speed')
  await page.getByLabel('目标服务地址').fill('http://127.0.0.1:18766')
  await page.locator('input[type=password]').fill(process.env.NETSCOPE_E2E_KEY!)
  await page.getByRole('button', {name: '开始测试'}).click()
  await expect(page.getByText('测试完成', {exact: true})).toBeVisible({timeout: 20_000})
  const row = page.getByRole('row').filter({hasText: '127.0.0.1:18766'})
  await expect(row).toContainText('回环')
  await expect(row).toContainText('Mbit/s')
})

test('navigate all workspace views and export a local traffic report', async ({page}) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await session(page)
  await expect(page.getByLabel('监控网卡')).toBeEnabled()
  await page.getByRole('button', {name: '30 秒'}).click()
  await expect(page.getByRole('button', {name: '30 秒'})).toHaveAttribute('aria-pressed', 'true')
  for (const [hash, heading] of [['devices','网络设备'],['packets','报文分析'],['speed','性能测试'],
    ['history','历史报告'],['alerts','异常告警'],['settings','设置']]) {
    await page.goto('/#' + hash)
    await expect(page.getByRole('heading', {name: heading, exact: true, level: 1})).toBeVisible()
  }
  await page.goto('/#history')
  const download = page.waitForEvent('download')
  await page.getByRole('link', {name: /CSV/}).click()
  expect((await download).suggestedFilename()).toMatch(/\.csv$/)
  expect(errors).toEqual([])
})

test('capture controls send a pre-filter and show its rejection before acquisition', async ({page}) => {
  await session(page)
  // A synthetic interface keeps this browser test independent of driver installation.
  await page.route('**/api/capture/interfaces', route => route.fulfill({json: [{name: 'test-adapter',description:'',is_up:true}]}))
  const capture = await page.request.get('/api/capture')
  expect(capture.ok()).toBeTruthy()
  const idle = {...await capture.json(), available: true, state: 'idle'}
  await page.route('**/api/capture', route => route.fulfill({json: idle}))
  await page.goto('/#packets')
  await page.getByLabel('捕获协议').selectOption('UDP')
  await page.getByLabel('捕获 IP').fill('192.0.2.1')
  await page.getByLabel('捕获端口').fill('5000')
  const start = page.waitForRequest(req => req.url().endsWith('/api/capture/start'))
  await page.getByRole('button',{name:'开始抓包'}).click()
  expect((await start).postDataJSON()).toMatchObject({interface:'test-adapter', protocol:'UDP',ip:'192.0.2.1',port:5000})
  await page.getByLabel('捕获条件').selectOption('expression')
  await page.getByLabel('BPF 捕获过滤器').fill('无效表达式')
  const rejected = page.waitForResponse(res => res.url().endsWith('/api/capture/start'))
  await page.getByRole('button',{name:'开始抓包'}).click()
  expect((await rejected).status()).toBe(422)
  await expect(page.getByRole('alert').filter({hasText:'ASCII'})).toBeVisible()
})

test('selected capture flow filters real decoded rows and persists a historical endpoint view', async ({page}) => {
  await session(page)
  await page.goto('/#packets')
  await page.locator('input[type=file]').setInputFiles({name:'flow.pcap',mimeType:'application/octet-stream',buffer:syntheticCapture})
  await page.getByRole('button',{name:'192.0.2.10 / 43211',exact:true}).click()
  await expect(page.getByRole('button',{name:'查看报文 1'})).toHaveCount(0)
  await page.getByRole('button',{name:'查看报文 2'}).click()
  await expect(page.getByText('UDP 首部',{exact:true})).toBeVisible()
  await page.goto('/#history?tab=captures&start=1700000000&end=1700000001')
  await expect(page.getByRole('heading',{name:'历史报文分析'})).toBeVisible()
  await page.getByRole('button',{name:'IP 端点',exact:true}).click()
  const endpoint = page.waitForResponse(r => new URL(r.url()).pathname === '/api/capture/analysis' &&
    new URL(r.url()).searchParams.get('ip') === '192.0.2.10')
  await page.getByRole('button',{name:'192.0.2.10',exact:true}).click()
  expect((await endpoint).ok()).toBeTruthy()
  await expect(page.getByRole('cell', {name:'198.51.100.20 / 5353',exact:true})).toBeVisible()
})

test('overview peak carries its interface and UTC minute to capture history', async ({page}) => {
  await session(page)
  const picker = page.getByLabel('监控网卡')
  await expect(picker).toHaveValue(/.+/)
  const iface = await picker.inputValue()
  await page.getByRole('button',{name:'分析收发合计峰值'}).click()
  await expect(page.getByRole('heading',{name:'历史报文分析'})).toBeVisible()
  const q = new URLSearchParams(new URL(page.url()).hash.split('?')[1])
  expect(q.get('interface')).toBe(iface)
  expect(Number(q.get('start')) % 60).toBe(0)
  expect(Number(q.get('end')) - Number(q.get('start'))).toBe(60)
  await expect(page.getByText('该时间段没有抓包记录', {exact:false}).first()).toBeVisible()
})

test('switch between three test modes and run a real sustained loopback measurement', async ({page}) => {
  await session(page)
  await page.goto('/#speed')
  const mode = page.getByLabel('测试方式')
  await mode.selectOption('repeated')
  await expect(page.getByLabel('每方向持续时间')).toHaveCount(0)
  await mode.selectOption('sustained')
  const duration = page.getByLabel('每方向持续时间')
  await duration.selectOption('10')
  await duration.selectOption('5')
  await page.getByLabel('目标服务地址').fill('http://127.0.0.1:18766')
  await page.locator('input[type=password]').fill(process.env.NETSCOPE_E2E_KEY!)
  const started = page.waitForResponse(r => r.request().method()==='POST' && r.url().endsWith('/api/speed'))
  await page.getByRole('button',{name:'开始测试'}).click()
  expect((await started).status()).toBe(202)
  await expect.poll(async () => (await (await page.request.get('/api/speed')).json()).result?.mode, {timeout:45000}).toBe('sustained')
  await expect(page.getByText('测试完成',{exact:true})).toBeVisible()
  const result = (await (await page.request.get('/api/speed')).json()).result
  expect(result.download_bytes).toBeGreaterThan(0)
  expect(result.upload_mbps).toBeCloseTo(result.upload_bytes * 8 / result.upload_seconds / 1e6, 4)
  await expect(page.getByRole('row').filter({hasText:'持续 · 每方向 5 秒'})).toContainText('回环')
})

test('an alert explains missing evidence and links to its interface and time range', async ({page}) => {
  await session(page)
  // The alert is a UI fixture. The linked history page uses the real local service.
  const window = {start: 1700000040, end: 1700000220, interface: 'fixture-adapter'}
  const event = {
    id: 73, ts: window.start + 60, interface: window.interface, kind: 'rx_rate',
    message: '测试告警', advice: '查看同期通信端点', recovered_at: null, acknowledged: false,
    observation: {observed_bps: 3000000, threshold_bps: 1000000, consecutive: 3},
  }
  await page.route('**/api/alerts', route => route.fulfill({json: {items: [event]}}))
  await page.route('**/api/alerts/73/diagnosis', route => route.fulfill({json: {
    event, window, counter: null, capture: null, speed_tests: [], possible: '需要同期数据判断',
    limitations: ['该时间段没有抓包记录。'], check: event.advice,
  }}))
  await page.goto('/#alerts')
  await page.getByRole('button', {name: '查看诊断依据'}).click()
  const evidence = page.getByRole('region', {name: '事件诊断依据'})
  await expect(evidence).toContainText('连续 3 个有效样本')
  await expect(evidence).toContainText('该时间段没有抓包记录。')
  await evidence.getByRole('link', {name: '同期抓包与端点'}).click()
  await expect(page.getByRole('heading', {name: '历史报文分析'})).toBeVisible()
  const params = new URLSearchParams(new URL(page.url()).hash.split('?')[1])
  expect(Object.fromEntries(params)).toEqual({
    tab: 'captures', start: String(window.start), end: String(window.end), interface: window.interface,
  })
})
