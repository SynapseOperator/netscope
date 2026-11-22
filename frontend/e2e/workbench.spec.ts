import { expect, test, type Page } from '@playwright/test'
import { randomBytes } from 'node:crypto'

const password = 'local-browser-test-password'
const username = () => 'operator-' + randomBytes(5).toString('hex')
const admin = username()

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
  const sample = Buffer.from('1MOyoQIABAAAAAAAAAAAAP//AAABAAAAAPFTZQAAAAA2AAAANgAAAAIAAAAAAgIAAAAAAQgARQAAKAABAABABo59wAACCsYzZBSoygG7AAAAAAAAAABQAiAA+QoAAADxU2UAAAAAKgAAACoAAAACAAAAAAICAAAAAAEIAEUAABwAAQAAQBGOfsAAAgrGM2QUqMsU6QAIVdc=', 'base64')
  await page.locator('input[type=file]').setInputFiles({name: 'synthetic.pcap', mimeType: 'application/octet-stream', buffer: sample})
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
