/* GoBAS Web GUI - 单文件 SPA（hash 路由 + 原生 JS，零构建依赖） */
'use strict';

/* ============ API 客户端 ============ */
const API = {
  async req(path, opts = {}) {
    const res = await fetch('/api/v1' + path, {
      headers: { 'Content-Type': 'application/json' },
      ...opts,
    });
    if (!res.ok) {
      // 会话失效（401）：业务接口统一跳登录页；登录/状态接口各自处理
      if (res.status === 401 && path !== '/auth/login' && path !== '/auth/status') {
        location.hash = '#/login';
      }
      let msg = `HTTP ${res.status}`;
      try { msg = (await res.json()).error || msg; } catch (e) {}
      throw new Error(msg);
    }
    return res.json();
  },
  get(path) { return this.req(path); },
  post(path, body) { return this.req(path, { method: 'POST', body: JSON.stringify(body || {}) }); },
  put(path, body) { return this.req(path, { method: 'PUT', body: JSON.stringify(body || {}) }); },
  del(path, body) {
    const opts = { method: 'DELETE' };
    if (body !== undefined) opts.body = JSON.stringify(body);
    return this.req(path, opts);
  },
};

/* ============ 工具函数 ============ */
const $ = (sel, el = document) => el.querySelector(sel);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));
const fmtTime = (s) => s ? s.replace('T', ' ').replace(/[Z+].*$/, '') : '-';
const fmtProtocols = (s) => {
  try { const a = JSON.parse(s || '[]'); return Array.isArray(a) && a.length ? a.join('/') : '-'; }
  catch (e) { return '-'; }
};
const severityBadge = (sev) => `<span class="badge badge-${esc((sev || 'unknown').toLowerCase())}">${esc((sev || 'unknown').toUpperCase())}</span>`;
// execBadge 标记模板可执行性。
// 索引时已过滤不可执行模板（headless/非支持协议/自包含/缺解释器/纯code），
// 入库的都是可执行的；混合 code 模板未通过官方签名的标记"重签后可执行"。
const execBadge = (p) => {
  const protos = p.Protocols || '[]';
  // 纯 code 模板（含 code 且不含 http/network/websocket）本地子进程发请求，无流量数据
  if (protos.includes('"code"') && !protos.includes('"http"') && !protos.includes('"network"') && !protos.includes('"websocket"')) return '<span class="badge badge-exec-no" title="纯 code 脚本模板：本地子进程发请求，无流量数据且依赖本机工具">不可执行</span>';
  // 混合 code 模板未通过官方签名，扫描时由本地签名器自动重签
  if (protos.includes('"code"') && !p.Verified) return '<span class="badge badge-exec-warn" title="code 模板未通过官方签名，扫描时自动重签">重签后可执行</span>';
  return '<span class="badge badge-exec-ok" title="引擎可加载执行">可执行</span>';
};
const verdictBadge = (v) => `<span class="verdict verdict-${esc(v)}">${esc(v)}</span>`;
const statusBadge = (s) => `<span class="status status-${esc(s)}">${esc(s)}</span>`;
// decodeSource 来源下拉（单一筛选）→ official/custom 过滤参数组合。
// 人工 POC 的 is_official 恒为 0：选官方源/社区源时用 custom=false 排除人工，
// 使「社区源」仅表示 git 拉取的社区仓库，「✎ 人工添加」独立成项。
const decodeSource = (v) => {
  switch (v) {
    case 'custom': return { official: '', custom: 'true' };
    case 'official': return { official: 'true', custom: 'false' };
    case 'community': return { official: 'false', custom: 'false' };
    default: return { official: '', custom: '' };
  }
};

function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.innerHTML = (type === 'success' ? '✓ ' : type === 'error' ? '✗ ' : 'ℹ ') + esc(msg);
  $('#toast-container').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

/* ============ 通用分页组件 ============ */
// pagerState 分页状态：{ page, pageSize, total }
const PAGE_SIZES = [10, 20, 50, 100];

// pagerHTML 生成分页条（含每页条数下拉）。
// onReload 为跳页/改每页条数后的重载回调，ID 前缀保证同页多分页条共存。
function pagerHTML(pfx, st) {
  const pages = Math.max(1, Math.ceil((st.total || 0) / st.pageSize));
  return `
    <div class="pagination" id="${pfx}-pager">
      <span>共 ${st.total || 0} 条 · 第 ${Math.min(st.page, pages)}/${pages} 页</span>
      <div class="page-size">
        每页
        <select class="page-size-select" id="${pfx}-pagesize">
          ${PAGE_SIZES.map((n) => `<option value="${n}" ${st.pageSize === n ? 'selected' : ''}>${n}</option>`).join('')}
        </select>
        条
      </div>
      <div class="pages">
        <button class="btn btn-sm" id="${pfx}-prev" ${st.page <= 1 ? 'disabled' : ''}>← 上一页</button>
        <button class="btn btn-sm" id="${pfx}-next" ${st.page >= pages ? 'disabled' : ''}>下一页 →</button>
      </div>
    </div>`;
}

// bindPager 绑定分页条交互：prev/next + 每页条数切换。
// onReload(page, pageSize) 在跳页后调用。
function bindPager(pfx, st, onReload) {
  const go = (p, ps) => {
    st.page = Math.max(1, Math.min(p, Math.max(1, Math.ceil((st.total || 0) / ps))));
    st.pageSize = ps;
    onReload(st.page, st.pageSize);
  };
  const prev = $(`#${pfx}-prev`);
  const next = $(`#${pfx}-next`);
  if (prev) prev.onclick = () => go(st.page - 1, st.pageSize);
  if (next) next.onclick = () => go(st.page + 1, st.pageSize);
  const psSel = $(`#${pfx}-pagesize`);
  if (psSel) psSel.onchange = () => go(1, Number(psSel.value) || st.pageSize);
}

function confirmBox(msg) { return window.confirm(msg); }

async function apiGuard(fn) {
  try { return await fn(); }
  catch (e) { toast(e.message, 'error'); throw e; }
}

/* ============ 路由 ============ */
const routes = {
  '/login': { title: '登录', render: renderLogin },
  '/change-password': { title: '修改密码', render: renderChangePassword },
  '/dashboard': { title: '仪表盘', render: renderDashboard },
  '/pocs': { title: 'POC 库', render: renderPOCs },
  '/poc-sets': { title: 'POC 模板集', render: renderPOCSets },
  '/poc-sets/:id': { title: '模板集详情', render: renderPOCSetDetail },
  '/targets': { title: '目标管理', render: renderTargets },
  '/scan/new': { title: '发起攻击模拟', render: renderScanNew },
  '/scans': { title: '扫描历史', render: renderScans },
  '/scans/:id': { title: '扫描详情', render: renderScanDetail },
  '/sync': { title: 'POC 源同步', render: renderSync },
};

let currentCleanup = null; // 页面切换时清理（如 SSE / 定时器）

// authState 当前认证状态（由 /auth/status 刷新）。
let authState = { enabled: true, authenticated: false, username: '', must_change_password: false };

// updateAuthUI 右上角用户胶囊显隐与用户名（仅认证启用且已登录时显示）。
function updateAuthUI() {
  const menu = $('#user-menu');
  if (!menu) return;
  const on = authState.enabled && authState.authenticated;
  menu.classList.toggle('hidden', !on);
  if (on) {
    const name = authState.username || '';
    const chip = $('#avatar-btn');
    if (chip) chip.title = name || '账户';
    const un = $('#uc-name');
    if (un) un.textContent = name;
  }
}

// ensureAuth 认证门：未登录 → 登录页；强制改密未完成 → 改密页。
// 返回 false 表示已发起跳转，当前路由不渲染。
async function ensureAuth() {
  try {
    const st = await API.get('/auth/status');
    authState = Object.assign({}, authState, st);
  } catch (e) {
    authState = { enabled: true, authenticated: false, username: '', must_change_password: false };
  }
  const p = location.hash;
  updateAuthUI();
  if (!authState.enabled) { // 认证关闭：全部放行
    document.body.classList.remove('auth-page');
    return true;
  }
  if (!authState.authenticated) {
    if (p !== '#/login') { location.hash = '#/login'; return false; }
    document.body.classList.add('auth-page'); // 登录页隐藏侧边栏
    return true;
  }
  document.body.classList.remove('auth-page');
  if (authState.must_change_password && p !== '#/change-password') {
    location.hash = '#/change-password';
    return false;
  }
  if (p === '#/login') { location.hash = '#/dashboard'; return false; }
  return true;
}

function matchRoute(hash) {
  // 剥离查询串（如 #/scan/new?set=2 → /scan/new）
  const path = (hash.replace(/^#/, '').split('?')[0]) || '/dashboard';
  for (const [pattern, route] of Object.entries(routes)) {
    const patParts = pattern.split('/');
    const pathParts = path.split('/');
    if (patParts.length !== pathParts.length) continue;
    const params = {};
    let ok = true;
    for (let i = 0; i < patParts.length; i++) {
      if (patParts[i].startsWith(':')) params[patParts[i].slice(1)] = decodeURIComponent(pathParts[i]);
      else if (patParts[i] !== pathParts[i]) { ok = false; break; }
    }
    if (ok) return { route, params, path };
  }
  return null;
}

async function router() {
  if (currentCleanup) { currentCleanup(); currentCleanup = null; }
  // 切换路由时收起右上角用户下拉
  const dd = $('#user-dropdown');
  if (dd) dd.classList.add('hidden');
  const m = matchRoute(location.hash);
  if (!m) { location.hash = '#/dashboard'; return; }
  // 认证门：未登录跳登录页；强制改密未完成跳改密页
  if (!(await ensureAuth())) return;
  // 导航高亮
  document.querySelectorAll('#nav a').forEach((a) => {
    const r = a.dataset.route;
    a.classList.toggle('active', m.path.startsWith(r.replace('new', 'new')) && (r !== '#/scans' || !m.path.startsWith('/scan')));
  });
  document.querySelectorAll('#nav a').forEach((a) => a.classList.remove('active'));
  const activeKey = Object.keys({ 'dashboard': 1, 'pocs': 1, 'poc-sets': 1, 'targets': 1, 'scan-new': 1, 'scans': 1, 'sync': 1 })
    .find((k) => {
      if (k === 'scan-new') return m.path === '/scan/new';
      return m.path.startsWith('/' + k);
    });
  if (activeKey) $(`#nav a[data-route="${activeKey}"]`)?.classList.add('active');

  const main = $('#main');
  main.innerHTML = '<div class="loading"><div class="spinner"></div>加载中...</div>';
  try { await m.route.render(main, m.params); }
  catch (e) {
    main.innerHTML = `<div class="empty"><div class="empty-icon">⚠</div><div>加载失败：${esc(e.message)}</div></div>`;
  }
}

window.addEventListener('hashchange', router);

/* ============ 视图：仪表盘 ============ */
async function renderDashboard(main) {
  const [stats, scans, targets] = await Promise.all([
    apiGuard(() => API.get('/pocs/stats')),
    apiGuard(() => API.get('/scans?limit=8')),
    apiGuard(() => API.get('/targets')),
  ]);
  const totalTargets = targets.targets?.length || 0;
  const aliveTargets = targets.targets?.filter((t) => t.Alive).length || 0;
  const sev = stats.BySeverity || {};
  const sevTotal = Object.values(sev).reduce((a, b) => a + b, 0) || 1;

  const sevColors = { critical: '#f85149', high: '#fb8a3d', medium: '#e3b341', low: '#58a6ff', info: '#8b949e', unknown: '#8b949e' };
  const distRows = Object.keys(sevColors).filter((k) => sev[k]).map((k) => `
    <div class="dist-row">
      <div class="dist-label">${k}</div>
      <div class="dist-bar"><div class="dist-fill" style="width:${((sev[k] / sevTotal) * 100).toFixed(1)}%;background:${sevColors[k]}"></div></div>
      <div class="dist-count">${sev[k]}</div>
    </div>`).join('');

  const scanRows = (scans.scans || []).map((sc) => `
    <tr class="clickable" onclick="location.hash='#/scans/${sc.ID}'">
      <td class="mono">#${sc.ID}</td>
      <td>${esc(sc.Name || '-')}</td>
      <td>${statusBadge(sc.Status)}</td>
      <td><span class="verdict verdict-HIT">${sc.HitCount}</span> <span class="verdict verdict-BLOCKED">${sc.BlockedCount}</span> <span class="verdict verdict-MISS">${sc.MissCount}</span></td>
      <td class="mono">${fmtTime(sc.StartedAt)}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="empty">暂无扫描记录</td></tr>';

  main.innerHTML = `
    <div class="page-header">
      <div><div class="page-title">仪表盘</div><div class="page-desc">GoBAS 整体态势一览</div></div>
      <div class="header-actions">
        <a class="btn btn-primary" href="#/scan/new">⚡ 发起攻击模拟</a>
      </div>
    </div>
    <div class="grid grid-4">
      <div class="card stat-card c-blue"><div class="stat-value">${stats.Total || 0}</div><div class="stat-label">POC 模板总数（官方 ${stats.Official || 0} · 人工 ${stats.Custom || 0}）</div></div>
      <div class="card stat-card c-green"><div class="stat-value">${aliveTargets}/${totalTargets}</div><div class="stat-label">存活目标 / 全部</div></div>
      <div class="card stat-card c-red"><div class="stat-value">${sev.critical || 0}</div><div class="stat-label">Critical 级 POC</div></div>
      <div class="card stat-card c-purple"><div class="stat-value">${stats.WithInteractsh || 0}</div><div class="stat-label">依赖 OOB 回连（默认排除）</div></div>
    </div>
    <div class="grid grid-2" style="margin-top:16px">
      <div class="card">
        <div class="card-title">POC 严重度分布</div>
        ${distRows || '<div class="empty">POC 库为空，请先 <a href="#/sync" style="color:var(--accent)">同步 POC 源</a></div>'}
      </div>
      <div class="card">
        <div class="card-title">最近扫描 <a class="btn btn-sm" href="#/scans" style="float:right">全部 →</a></div>
        <div class="table-wrap" style="border:none">
          <table>
            <thead><tr><th>ID</th><th>名称</th><th>状态</th><th>HIT/BLOCK/MISS</th><th>时间</th></tr></thead>
            <tbody>${scanRows}</tbody>
          </table>
        </div>
      </div>
    </div>`;
}

/* ============ 视图：POC 库 ============ */
const pocState = { page: 1, pageSize: 20, severity: '', tag: '', search: '', protocol: '', source: '', noInteractsh: false };
// 跨页勾选（翻页/改过滤不丢）：Map<pocID, 模板ID>
const pocSelection = new Map();

function updatePocSelectionBar() {
  const bar = $('#poc-sel-bar');
  if (!bar) return;
  const n = pocSelection.size;
  bar.style.display = n > 0 ? 'flex' : 'none';
  const cnt = $('#poc-sel-count');
  if (cnt) cnt.textContent = n;
}

async function renderPOCs(main) {
  main.innerHTML = `
    <div class="page-header">
      <div><div class="page-title">POC 模板库</div><div class="page-desc">已索引的 nuclei 模板，勾选加入模板集（跨页保留）；人工添加的模板独立于自动拉取源</div></div>
      <div class="header-actions"><button class="btn btn-primary" id="btn-add-custom-poc">＋ 人工添加 POC</button><a class="btn" href="#/poc-sets">📁 模板集</a><a class="btn" href="#/sync">🔄 同步源仓库</a></div>
    </div>
    <div class="card">
      <div class="filter-bar">
        <div class="form-item grow"><label>关键词</label>
          <input type="text" id="f-search" placeholder="模板ID / 名称 / 标签 / CVE / CNVD" value="${esc(pocState.search)}"></div>
        <div class="form-item"><label>来源</label>
          <select id="f-source">
            <option value="">全部</option>
            <option value="custom" ${pocState.source === 'custom' ? 'selected' : ''}>✎ 人工添加</option>
            <option value="official" ${pocState.source === 'official' ? 'selected' : ''}>★ 官方源</option>
            <option value="community" ${pocState.source === 'community' ? 'selected' : ''}>社区源</option>
          </select></div>
        <div class="form-item"><label>协议</label>
          <select id="f-protocol">
            <option value="">全部</option>
            ${['http', 'websocket', 'code', 'dns', 'network', 'ssl', 'headless', 'file', 'whois'].map((p) => `<option value="${p}" ${pocState.protocol === p ? 'selected' : ''}>${p}</option>`).join('')}
          </select></div>
        <div class="form-item"><label>严重度</label>
          <select id="f-severity">
            <option value="">全部</option>
            ${['critical', 'high', 'medium', 'low', 'info'].map((s) => `<option value="${s}" ${pocState.severity === s ? 'selected' : ''}>${s}</option>`).join('')}
          </select></div>
        <div class="form-item"><label>标签</label>
          <input type="text" id="f-tag" placeholder="如 cve、rce" value="${esc(pocState.tag)}"></div>
        <div class="form-item" style="min-width:auto;justify-content:flex-end">
          <button class="btn btn-primary" id="f-go">查询</button></div>
      </div>
      <label class="checkbox-item" style="margin-bottom:12px">
        <input type="checkbox" id="f-nointer" ${pocState.noInteractsh ? 'checked' : ''}>
        排除依赖 OOB 回连（Interactsh）的模板 —— 无外网回连环境下建议勾选
      </label>
      <div id="poc-table"></div>
    </div>
    <div class="poc-sel-bar" id="poc-sel-bar" style="display:none">
      <span>已选 <b id="poc-sel-count">0</b> 个 POC</span>
      <button class="btn btn-sm btn-primary" id="poc-sel-add">＋ 加入模板集</button>
      <button class="btn btn-sm" id="poc-sel-clear">清空选择</button>
    </div>`;

  const load = async () => {
    pocState.search = $('#f-search').value.trim();
    pocState.source = $('#f-source').value;
    pocState.protocol = $('#f-protocol').value;
    pocState.severity = $('#f-severity').value;
    pocState.tag = $('#f-tag').value.trim();
    pocState.noInteractsh = $('#f-nointer').checked;
    await loadPOCTable($('#poc-table'), pocState);
    updatePocSelectionBar();
  };
  $('#f-go').onclick = () => { pocState.page = 1; load(); };
  $('#f-search').onkeydown = (e) => { if (e.key === 'Enter') { pocState.page = 1; load(); } };
  $('#f-nointer').onchange = () => { pocState.page = 1; load(); };
  $('#btn-add-custom-poc').onclick = () => showCustomPOCModal();
  $('#poc-sel-clear').onclick = () => { pocSelection.clear(); document.querySelectorAll('.p-check').forEach((c) => (c.checked = false)); updatePocSelectionBar(); };
  $('#poc-sel-add').onclick = showAddToSetModal;
  await load();
}

async function loadPOCTable(el, state) {
  el.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
  const src = decodeSource(state.source);
  const q = new URLSearchParams({
    limit: String(state.pageSize),
    offset: String((state.page - 1) * state.pageSize),
    severity: state.severity,
    tag: state.tag,
    search: state.search,
    protocol: state.protocol,
    official: src.official,
    custom: src.custom,
    no_interactsh: state.noInteractsh ? 'true' : '',
  });
  try {
    const data = await API.get('/pocs?' + q.toString());
    const pocs = data.pocs || [];
    const total = data.total || 0;
    const pages = Math.max(1, Math.ceil(total / state.pageSize));

    const allChecked = pocs.length > 0 && pocs.every((p) => pocSelection.has(p.ID));
    el.innerHTML = `
      <div class="table-wrap" style="border:none">
        <table>
          <thead><tr><th style="width:32px"><input type="checkbox" id="pg-check-all" ${allChecked ? 'checked' : ''} title="本页全选"></th><th>ID</th><th>模板 ID</th><th>名称</th><th>严重度</th><th>协议</th><th>标签</th><th>CVE</th><th>来源</th><th></th></tr></thead>
          <tbody>
            ${pocs.map((p) => `
              <tr>
                <td><input type="checkbox" class="p-check" data-pid="${p.ID}" data-tid="${esc(p.TemplateID)}" ${pocSelection.has(p.ID) ? 'checked' : ''}></td>
                <td class="mono">${p.ID}</td>
                <td class="mono ellipsis" title="${esc(p.TemplateID)}">${esc(p.TemplateID)}</td>
                <td class="ellipsis" title="${esc(p.Name)}">${esc(p.Name)}</td>
                <td>${severityBadge(p.Severity)}</td>
                <td class="mono" style="font-size:12px">${esc(fmtProtocols(p.Protocols))} ${execBadge(p)}</td>
                <td class="ellipsis mono" style="max-width:180px" title="${esc(p.Tags)}">${esc(p.Tags.replace(/,/g, ' ').trim())}</td>
                <td class="mono">${esc(p.CVEIDs || '-')}</td>
                <td class="mono ellipsis" style="max-width:160px" title="${esc(p.SourceRepo)}">${p.IsCustom ? '<span class="badge badge-custom">✎ 人工</span>' : (p.IsOfficial ? '★ ' : '') + esc(p.SourceRepo)}</td>
                <td style="white-space:nowrap">
                  ${p.IsCustom ? `<button class="btn btn-sm" onclick="showCustomPOCModal(${p.ID})">编辑</button>
                  <button class="btn btn-sm btn-danger" onclick="deleteCustomPOC(${p.ID}, '${esc(p.TemplateID)}')">删除</button>` : ''}
                  <button class="btn btn-sm" onclick="showPOCModal(${p.ID})">详情</button>
                </td>
              </tr>`).join('') || '<tr><td colspan="10" class="empty">无匹配 POC（请先同步源并建立索引，或人工添加 POC）</td></tr>'}
          </tbody>
        </table>
      </div>
      <div class="pagination">
        <span>共 ${total} 条 · 第 ${state.page}/${pages} 页</span>
        <div class="page-size">
          每页
          <select class="page-size-select" id="pg-pagesize">
            ${PAGE_SIZES.map((n) => `<option value="${n}" ${state.pageSize === n ? 'selected' : ''}>${n}</option>`).join('')}
          </select>
          条
        </div>
        <div class="pages">
          <button class="btn btn-sm" ${state.page <= 1 ? 'disabled' : ''} id="pg-prev">← 上一页</button>
          <button class="btn btn-sm" ${state.page >= pages ? 'disabled' : ''} id="pg-next">下一页 →</button>
        </div>
      </div>`;
    $('#pg-prev')?.addEventListener('click', () => { state.page--; loadPOCTable(el, state); });
    $('#pg-next')?.addEventListener('click', () => { state.page++; loadPOCTable(el, state); });
    $('#pg-pagesize')?.addEventListener('change', (e) => {
      const n = Number(e.target.value) || state.pageSize;
      if (n !== state.pageSize) { state.pageSize = n; state.page = 1; loadPOCTable(el, state); }
    });

    // 行勾选（跨页保留在 Map）
    document.querySelectorAll('.p-check').forEach((c) => {
      c.onchange = () => {
        const pid = Number(c.dataset.pid);
        if (c.checked) pocSelection.set(pid, c.dataset.tid);
        else pocSelection.delete(pid);
        updatePocSelectionBar();
      };
    });
    // 本页全选/取消
    $('#pg-check-all')?.addEventListener('change', (e) => {
      document.querySelectorAll('.p-check').forEach((c) => {
        const pid = Number(c.dataset.pid);
        if (e.target.checked) { pocSelection.set(pid, c.dataset.tid); c.checked = true; }
        else { pocSelection.delete(pid); c.checked = false; }
      });
      updatePocSelectionBar();
    });
  } catch (e) {
    el.innerHTML = `<div class="empty">加载失败：${esc(e.message)}</div>`;
  }
}

/* POC 详情弹窗 */
async function showPOCModal(id) {
  try {
    const p = await API.get(`/pocs/${id}`);
    let yamlSection = '';
    try {
      const c = await API.get(`/pocs/${id}/content`);
      yamlSection = `
        <div style="margin-top:14px">
          <div style="font-size:12px;color:var(--muted);margin-bottom:6px">模板 YAML 原文</div>
          <textarea readonly style="width:100%;min-height:200px;font-size:12px" id="pm-yaml">${esc(c.content || '')}</textarea>
        </div>`;
    } catch (e) { /* 内容读取失败不阻塞详情展示 */ }
    $('#modal-root').innerHTML = `
      <div class="modal-overlay" onclick="if(event.target===this)closeModal()">
        <div class="modal">
          <div class="modal-header">
            <h3>${esc(p.TemplateID)} ${severityBadge(p.Severity)} ${p.IsCustom ? '<span class="badge badge-custom">✎ 人工</span>' : ''}</h3>
            <button class="modal-close" onclick="closeModal()">×</button>
          </div>
          <div class="modal-body">
            <dl class="kv-list">
              <dt>名称</dt><dd>${esc(p.Name)}</dd>
              <dt>作者</dt><dd>${esc(p.Authors || '-')}</dd>
              <dt>标签</dt><dd class="mono">${esc(p.Tags.replace(/,/g, ' ').trim())}</dd>
              <dt>CVE</dt><dd class="mono">${esc(p.CVEIDs || '-')}</dd>
              <dt>CNVD</dt><dd class="mono">${esc(p.CNVDIDs || '-')}</dd>
              <dt>CWE</dt><dd class="mono">${esc(p.CWEIDs || '-')}</dd>
              <dt>CVSS</dt><dd class="mono">${p.CVSSScore || '-'}</dd>
              <dt>协议</dt><dd class="mono">${esc(p.Protocols)}</dd>
              <dt>OOB 回连</dt><dd>${p.HasInteractsh ? '⚠ 依赖 Interactsh' : '否'}</dd>
              <dt>来源</dt><dd class="mono">${p.IsCustom ? '✎ 人工添加' : (p.IsOfficial ? '★ ' : '') + esc(p.SourceRepo)}</dd>
              <dt>文件路径</dt><dd class="mono">${esc(p.FilePath)}</dd>
              <dt>入库时间</dt><dd class="mono">${fmtTime(p.IndexedAt)}</dd>
            </dl>
            ${yamlSection}
            <button class="btn btn-primary" style="width:100%;margin-top:14px" id="pm-add-set">＋ 加入模板集</button>
            ${p.IsCustom ? `
            <div style="display:flex;gap:8px;margin-top:8px">
              <button class="btn" style="flex:1" id="pm-edit">✎ 编辑模板</button>
              <button class="btn btn-danger" style="flex:1" id="pm-del">🗑 删除</button>
            </div>` : ''}
          </div>
        </div>
      </div>`;
    $('#pm-add-set').onclick = () => showAddToSetModal([id], p.TemplateID);
    if (p.IsCustom) {
      $('#pm-edit')?.addEventListener('click', () => showCustomPOCModal(id));
      $('#pm-del')?.addEventListener('click', () => { closeModal(); deleteCustomPOC(id, p.TemplateID); });
    }
  } catch (e) { toast(e.message, 'error'); }
}

/* 人工添加/编辑 POC 弹窗（id 为空 = 添加，否则编辑回显） */
async function showCustomPOCModal(id) {
  let title = '人工添加 POC';
  let content = '';
  if (id) {
    try {
      const p = await API.get(`/pocs/${id}`);
      if (!p.IsCustom) { toast('仅人工添加的 POC 支持编辑', 'error'); return; }
      const c = await API.get(`/pocs/${id}/content`);
      content = c.content || '';
      title = `编辑人工 POC：${p.TemplateID}`;
    } catch (e) { toast(e.message, 'error'); return; }
  }
  $('#modal-root').innerHTML = `
    <div class="modal-overlay" onclick="if(event.target===this)closeModal()">
      <div class="modal" style="width:760px">
        <div class="modal-header">
          <h3>${esc(title)}</h3>
          <button class="modal-close" onclick="closeModal()">×</button>
        </div>
        <div class="modal-body">
          <div style="font-size:12px;color:var(--muted);margin-bottom:8px">
            粘贴 nuclei 模板 YAML。要求：模板 ID 唯一；支持 http/websocket/network 协议（含混合 code）；
            不支持 headless/自包含/OOB 回连/需凭证输入/纯 code 模板。提交后将通过引擎真实加载验证。
          </div>
          <textarea id="cp-content" style="width:100%;min-height:320px;font-size:12px" placeholder="id: my-custom-poc&#10;info:&#10;  name: 自定义检测模板&#10;  severity: high&#10;http:&#10;  - method: GET&#10;    path: &#34;/{{BaseURL}}/vulnerable-path&#34;&#10;    matchers:&#10;      - type: status&#10;        status: [200]">${esc(content)}</textarea>
          <button class="btn btn-primary" style="width:100%;margin-top:12px" id="cp-go">${id ? '保存修改' : '验证并添加'}</button>
        </div>
      </div>
    </div>`;
  const btn = $('#cp-go');
  btn.onclick = async () => {
    const yaml = $('#cp-content').value;
    if (!yaml.trim()) { toast('模板内容为空', 'error'); return; }
    btn.disabled = true;
    btn.textContent = '引擎验证中…';
    try {
      if (id) {
        await API.put(`/pocs/custom/${id}`, { content: yaml });
        toast('修改成功', 'success');
      } else {
        const p = await API.post('/pocs/custom', { content: yaml });
        toast(`添加成功：${p.TemplateID}（ID ${p.ID}）`, 'success');
      }
      closeModal();
      // 刷新当前 POC 列表（详情/列表页均可触发）
      const el = $('#poc-table');
      if (el) await loadPOCTable(el, pocState);
    } catch (e) {
      toast(e.message, 'error');
      btn.disabled = false;
      btn.textContent = id ? '保存修改' : '验证并添加';
    }
  };
}

/* 删除人工 POC */
async function deleteCustomPOC(id, templateID) {
  if (!confirmBox(`确认删除人工 POC "${templateID}"？\n（模板文件与模板集引用将一并移除，历史扫描结果保留）`)) return;
  try {
    await API.del(`/pocs/custom/${id}`);
    toast('已删除', 'success');
    pocSelection.delete(id);
    updatePocSelectionBar();
    const el = $('#poc-table');
    if (el) await loadPOCTable(el, pocState);
  } catch (e) { toast(e.message, 'error'); }
}

/* "加入模板集"弹窗：选已有集 / 新建。
   ids 为数组 = 指定 POC（允许空数组，用于纯新建空集）；否则取跨页勾选。 */
async function showAddToSetModal(ids, label) {
  const specified = Array.isArray(ids);
  const list = specified ? ids : [...pocSelection.keys()];
  if (!list.length && !specified) { toast('请先勾选 POC', 'error'); return; }
  const title = label ? `加入模板集：${label}` : `加入模板集（${list.length} 个 POC）`;
  let sets = [];
  try { sets = (await API.get('/poc-sets')).sets || []; } catch (e) { /* 列表加载失败仍允许新建 */ }
  $('#modal-root').innerHTML = `
    <div class="modal-overlay" onclick="if(event.target===this)closeModal()">
      <div class="modal">
        <div class="modal-header">
          <h3>${esc(title)}</h3>
          <button class="modal-close" onclick="closeModal()">×</button>
        </div>
        <div class="modal-body">
          <div class="form-item" style="margin-bottom:14px"><label>加入已有模板集</label>
            <select id="as-set"><option value="">— 选择模板集 —</option>
              ${sets.map((s) => `<option value="${s.id}">${esc(s.name)}（${s.poc_count} 个 POC）</option>`).join('')}
            </select>
          </div>
          <div style="text-align:center;color:var(--muted);font-size:12px;margin:2px 0 12px">—— 或 ——</div>
          <div class="form-item" style="margin-bottom:14px"><label>新建模板集</label>
            <input type="text" id="as-new-name" placeholder="模板集名称（如：Log4j 专项）">
          </div>
          <div class="form-item" style="margin-bottom:8px"><label>备注（可选）</label>
            <input type="text" id="as-desc" placeholder="用途说明">
          </div>
          <button class="btn btn-primary" id="as-go" style="width:100%;margin-top:8px">确认加入</button>
        </div>
      </div>
    </div>`;
  $('#as-go').onclick = async () => {
    const setName = $('#as-new-name').value.trim();
    const setID = Number($('#as-set').value) || 0;
    try {
      let res;
      if (setName) {
        res = await API.post('/poc-sets', { name: setName, description: $('#as-desc').value.trim(), poc_ids: list });
        toast(`已创建 "${res.name}"（${res.poc_count} 个 POC）`, 'success');
      } else if (setID) {
        res = await API.post(`/poc-sets/${setID}/pocs`, { poc_ids: list });
        toast(`已加入 ${res.added} 个 POC（重复自动跳过）`, 'success');
      } else {
        toast('请选择模板集或输入新名称', 'error'); return;
      }
      if (!specified) { // 跨页勾选场景：成功后清空勾选
        pocSelection.clear();
        document.querySelectorAll('.p-check').forEach((c) => (c.checked = false));
        updatePocSelectionBar();
      }
      // 展示可执行性分类提醒
      showClassificationResult(res.classification, setName || `模板集 #${setID}`);
    } catch (e) { toast(e.message, 'error'); }
  };
}

// showClassificationResult 在加入模板集后展示不可执行模板提醒弹窗。
// classification 为后端返回的逐项分类结果数组。
function showClassificationResult(classification, setName) {
  if (!classification || !classification.length) { closeAndRefreshSets(); return; }
  const nonExec = classification.filter((c) => !c.executable);
  if (nonExec.length === 0) { closeAndRefreshSets(); return; }
  // 按原因分组计数
  const byReason = {};
  nonExec.forEach((c) => { byReason[c.reason] = (byReason[c.reason] || 0) + 1; });
  const reasonText = Object.entries(byReason).map(([k, v]) => `${k} × ${v}`).join('、');
  const execCount = classification.length - nonExec.length;
  closeModal();
  $('#modal-root').innerHTML = `
    <div class="modal-overlay" onclick="if(event.target===this)closeModal()">
      <div class="modal">
        <div class="modal-header">
          <h3>⚠️ 模板可执行性提醒</h3>
          <button class="modal-close" onclick="closeModal()">×</button>
        </div>
        <div class="modal-body">
          <div style="margin-bottom:12px">
            <b>${esc(setName)}</b>：共 ${classification.length} 个 POC，其中
            <span style="color:var(--green)">${execCount} 个可执行</span>，
            <span style="color:var(--red)">${nonExec.length} 个不可执行</span>
          </div>
          <div class="card" style="background:var(--bg2);padding:10px 14px;margin-bottom:12px">
            <div style="font-size:13px;color:var(--muted);margin-bottom:4px">跳过原因汇总</div>
            <div style="font-size:14px">${esc(reasonText)}</div>
          </div>
          <details style="margin-bottom:12px">
            <summary style="cursor:pointer;font-size:13px;color:var(--muted)">查看不可执行模板列表（${nonExec.length}）</summary>
            <div class="table-wrap" style="max-height:300px;overflow-y:auto;margin-top:8px;border:none">
              <table>
                <thead><tr><th>模板 ID</th><th>名称</th><th>原因</th></tr></thead>
                <tbody>
                  ${nonExec.map((c) => `
                    <tr>
                      <td class="mono ellipsis" title="${esc(c.template_id)}">${esc(c.template_id)}</td>
                      <td class="ellipsis" title="${esc(c.name)}">${esc(c.name)}</td>
                      <td style="font-size:12px;color:var(--red)">${esc(c.reason)}</td>
                    </tr>`).join('')}
                </tbody>
              </table>
            </div>
          </details>
          <div style="font-size:12px;color:var(--muted);margin-bottom:12px">
            不可执行的模板已加入模板集，但发起攻击模拟时会自动跳过（不产生判定结果）
          </div>
          <button class="btn btn-primary" style="width:100%" onclick="closeAndRefreshSets()">知道了</button>
        </div>
      </div>
    </div>`;
}

function closeModal() { $('#modal-root').innerHTML = ''; }

// closeAndRefreshSets 关闭弹窗并刷新模板集列表（仅在模板集页面生效）。
// 修复：新建/加入模板集后列表不自动刷新，需手动刷新页面才能看到新集合。
function closeAndRefreshSets() {
  closeModal();
  if (location.hash.startsWith('#/poc-sets')) router();
}

/* ============ 视图：POC 模板集 ============ */
async function renderPOCSets(main) {
  const data = await apiGuard(() => API.get('/poc-sets'));
  const sets = data.sets || [];
  // 本地分页（模板集数量通常不大，一次拉全量）
  const pager = { page: 1, pageSize: 10, total: sets.length };
  const selSets = new Set(); // 批量删除勾选

  const body = `
    <div class="page-header">
      <div><div class="page-title">POC 模板集</div>
      <div class="page-desc">自由组装的 POC 分组（如专项漏洞、等保高危），发起攻击模拟时可直接选用</div></div>
      <div class="header-actions"><a class="btn" href="#/pocs">📦 去勾选 POC</a></div>
    </div>
    <div class="card">
      <div class="card-title">模板集列表（${sets.length}）
        <button class="btn btn-sm btn-primary" id="ps-new">＋ 新建模板集</button>
      </div>
      <div class="table-wrap" style="border:none">
        <table>
          <thead><tr><th style="width:32px"><input type="checkbox" id="ps-check-all" title="全选本页"></th><th>ID</th><th>名称</th><th>备注</th><th>POC 数</th><th>创建时间</th><th></th></tr></thead>
          <tbody id="ps-tbody"></tbody>
        </table>
      </div>
      <div id="ps-pager-wrap"></div>
    </div>
    <div class="poc-sel-bar" id="ps-sel-bar" style="display:none">
      <span>已选 <b id="ps-sel-count">0</b> 个模板集</span>
      <button class="btn btn-sm btn-danger" id="ps-del-batch">🗑 删除所选</button>
      <button class="btn btn-sm" id="ps-sel-clear">清空选择</button>
    </div>`;
  main.innerHTML = body;

  const renderRows = () => {
    const start = (pager.page - 1) * pager.pageSize;
    const pageSets = sets.slice(start, start + pager.pageSize);
    const allChecked = pageSets.length > 0 && pageSets.every((s) => selSets.has(s.id));
    $('#ps-tbody').innerHTML = pageSets.map((s) => `
      <tr class="clickable" onclick="location.hash='#/poc-sets/${s.id}'">
        <td><input type="checkbox" class="ps-check" value="${s.id}" onclick="event.stopPropagation()" ${selSets.has(s.id) ? 'checked' : ''}></td>
        <td class="mono">${s.id}</td>
        <td><b>${esc(s.name)}</b></td>
        <td class="ellipsis" style="max-width:280px" title="${esc(s.description)}">${esc(s.description || '-')}</td>
        <td class="mono">${s.poc_count}</td>
        <td class="mono">${fmtTime(s.created_at)}</td>
        <td>
          <button class="btn btn-sm" onclick="event.stopPropagation();location.hash='#/scan/new?set=${s.id}'">⚡ 用此集模拟</button>
          <button class="btn btn-sm btn-danger" onclick="event.stopPropagation();deletePOCSet(${s.id},'${esc(s.name)}')">删除</button>
        </td>
      </tr>`).join('') || '<tr><td colspan="7" class="empty">暂无模板集 —— 到 <a href="#/pocs" style="color:var(--accent)">POC 库</a> 勾选 POC 后"加入模板集"</td></tr>';
    $('#ps-pager-wrap').innerHTML = pagerHTML('ps', pager);
    bindPager('ps', pager, () => renderRows());
    $('#ps-check-all').checked = allChecked;
    updateSelBar();
  };

  const updateSelBar = () => {
    const n = selSets.size;
    $('#ps-sel-bar').style.display = n > 0 ? 'flex' : 'none';
    $('#ps-sel-count').textContent = n;
  };

  // 行勾选
  $('#ps-tbody').addEventListener('change', (e) => {
    const cb = e.target.closest('.ps-check');
    if (!cb) return;
    cb.checked ? selSets.add(Number(cb.value)) : selSets.delete(Number(cb.value));
    $('#ps-check-all').checked = [...document.querySelectorAll('.ps-check')].every((c) => c.checked);
    updateSelBar();
  });
  // 全选本页
  $('#ps-check-all').addEventListener('change', (e) => {
    document.querySelectorAll('.ps-check').forEach((c) => {
      c.checked = e.target.checked;
      e.target.checked ? selSets.add(Number(c.value)) : selSets.delete(Number(c.value));
    });
    updateSelBar();
  });
  $('#ps-sel-clear').onclick = () => {
    selSets.clear();
    document.querySelectorAll('.ps-check').forEach((c) => { c.checked = false; });
    $('#ps-check-all').checked = false;
    updateSelBar();
  };
  $('#ps-del-batch').onclick = async () => {
    const ids = [...selSets];
    if (!ids.length) return;
    if (!confirmBox(`确认删除所选 ${ids.length} 个模板集？\n（不影响 POC 库本身）`)) return;
    let ok = 0, fail = 0;
    for (const id of ids) {
      try { await API.del(`/poc-sets/${id}`); ok++; }
      catch (e) { fail++; toast(`#${id} 删除失败：${e.message}`, 'error'); }
    }
    if (ok > 0) toast(`已删除 ${ok} 个模板集${fail ? `（${fail} 个失败）` : ''}`, 'success');
    router();
  };
  $('#ps-new').onclick = () => showAddToSetModal([], null);
  renderRows();
}

async function deletePOCSet(id, name) {
  if (!confirmBox(`确认删除模板集 "${name}"？（不影响 POC 库本身）`)) return;
  try { await API.del(`/poc-sets/${id}`); toast('已删除', 'success'); router(); }
  catch (e) { toast(e.message, 'error'); }
}

async function renderPOCSetDetail(main, params) {
  const id = params.id;
  let data;
  try { data = await API.get(`/poc-sets/${id}`); }
  catch (e) { main.innerHTML = `<div class="empty">加载失败：${esc(e.message)}</div>`; return; }
  const set = data.set;
  const pocs = data.pocs || [];
  const bySev = {};
  pocs.forEach((p) => { bySev[p.Severity] = (bySev[p.Severity] || 0) + 1; });
  // 本地分页
  const pager = { page: 1, pageSize: 20, total: pocs.length };

  main.innerHTML = `
    <div class="page-header">
      <div><div class="page-title">📁 ${esc(set.name)}</div>
      <div class="page-desc">${esc(set.description || '无备注')} · 创建于 ${fmtTime(set.created_at)}</div></div>
      <div class="header-actions">
        <a class="btn btn-primary" href="#/scan/new?set=${set.id}">⚡ 用此集发起模拟</a>
        <button class="btn" id="sd-rename">✏️ 改名</button>
      </div>
    </div>
    <div class="grid grid-4" style="margin-bottom:16px">
      <div class="card stat-card c-blue"><div class="stat-value">${pocs.length}</div><div class="stat-label">POC 总数</div></div>
      <div class="card stat-card c-red"><div class="stat-value">${bySev.critical || 0}</div><div class="stat-label">Critical</div></div>
      <div class="card stat-card c-purple"><div class="stat-value">${pocs.filter((p) => p.HasInteractsh).length}</div><div class="stat-label">依赖 OOB 回连</div></div>
      <div class="card stat-card c-green"><div class="stat-value">${pocs.filter((p) => p.IsOfficial).length}</div><div class="stat-label">官方源模板</div></div>
    </div>
    <div class="card">
      <div class="card-title">集内 POC（${pocs.length}）
        <div>
          <button class="btn btn-sm" id="sd-sel-all">全选</button>
          <button class="btn btn-sm btn-danger" id="sd-remove-sel">移除所选</button>
          <button class="btn btn-sm btn-danger" id="sd-clear" onclick="clearPOCSet(${set.id},'${esc(set.name)}')">清空</button>
        </div>
      </div>
      <div class="table-wrap" style="border:none">
        <table>
          <thead><tr><th style="width:32px"><input type="checkbox" id="sd-check-all"></th><th>ID</th><th>模板 ID</th><th>名称</th><th>严重度</th><th>CVE</th><th>来源</th></tr></thead>
          <tbody id="sd-tbody"></tbody>
        </table>
      </div>
      <div id="sd-pager-wrap"></div>
    </div>`;

  const renderRows = () => {
    const start = (pager.page - 1) * pager.pageSize;
    const pagePocs = pocs.slice(start, start + pager.pageSize);
    // 全选状态由 refreshCheckAll 统一计算（仅当前页）
    $('#sd-tbody').innerHTML = pagePocs.map((p) => `
      <tr>
        <td><input type="checkbox" class="sd-check" value="${p.ID}"></td>
        <td class="mono">${p.ID}</td>
        <td class="mono ellipsis" title="${esc(p.TemplateID)}">${esc(p.TemplateID)}</td>
        <td class="ellipsis" title="${esc(p.Name)}">${esc(p.Name)}</td>
        <td>${severityBadge(p.Severity)}</td>
        <td class="mono">${esc(p.CVEIDs || '-')}</td>
        <td class="mono ellipsis" style="max-width:160px" title="${esc(p.SourceRepo)}">${p.IsOfficial ? '★ ' : ''}${esc(p.SourceRepo)}</td>
      </tr>`).join('') || '<tr><td colspan="7" class="empty">空模板集 —— 到 <a href="#/pocs" style="color:var(--accent)">POC 库</a> 勾选后加入</td></tr>';
    $('#sd-pager-wrap').innerHTML = pagerHTML('sd', pager);
    bindPager('sd', pager, () => renderRows());
    refreshCheckAll();
  };

  // refreshCheckAll 刷新全选框状态（考虑翻页：只统计当前页）
  const refreshCheckAll = () => {
    const boxes = [...document.querySelectorAll('#sd-tbody .sd-check')];
    $('#sd-check-all').checked = boxes.length > 0 && boxes.every((c) => c.checked);
  };

  $('#sd-sel-all').onclick = () => {
    // 全选按钮切换当前页所有行；若当前页全选则取消
    const boxes = [...document.querySelectorAll('#sd-tbody .sd-check')];
    const allOn = boxes.length > 0 && boxes.every((c) => c.checked);
    boxes.forEach((c) => (c.checked = !allOn));
    refreshCheckAll();
  };
  $('#sd-check-all')?.addEventListener('change', (e) => document.querySelectorAll('#sd-tbody .sd-check').forEach((c) => (c.checked = e.target.checked)));
  $('#sd-tbody').addEventListener('change', (e) => {
    if (e.target.closest('.sd-check')) refreshCheckAll();
  });
  $('#sd-remove-sel').onclick = async () => {
    const ids = [...document.querySelectorAll('.sd-check:checked')].map((c) => Number(c.value));
    if (!ids.length) { toast('请先勾选要移除的 POC', 'error'); return; }
    try {
      const res = await API.del(`/poc-sets/${id}/pocs`, { poc_ids: ids });
      toast(`已移除 ${res.removed} 个`, 'success');
      router();
    } catch (e) { toast(e.message, 'error'); }
  };
  $('#sd-rename').onclick = async () => {
    const name = prompt('新名称：', set.name);
    if (!name || name === set.name) return;
    try { await API.put(`/poc-sets/${id}`, { name }); toast('已改名', 'success'); router(); }
    catch (e) { toast(e.message, 'error'); }
  };
  renderRows();
}

async function clearPOCSet(id, name) {
  if (!confirmBox(`确认清空模板集 "${name}" 的全部 POC？`)) return;
  try {
    const res = await API.del(`/poc-sets/${id}/pocs`, { poc_ids: [] });
    toast(`已清空（移除 ${res.removed} 个）`, 'success');
    router();
  } catch (e) { toast(e.message, 'error'); }
}

/* ============ 视图：目标管理 ============ */
async function renderTargets(main) {
  const data = await apiGuard(() => API.get('/targets'));
  const targets = data.targets || [];
  // 本地分页
  const pager = { page: 1, pageSize: 20, total: targets.length };
  const selTargets = new Set(); // 批量勾选的目标 ID

  main.innerHTML = `
    <div class="page-header">
      <div><div class="page-title">目标管理</div><div class="page-desc">攻击模拟的目标资产（添加时自动基线探活）</div></div>
    </div>
    <div class="card">
      <div class="card-title">添加目标</div>
      <div class="form-grid">
        <div class="form-item" style="grid-column:1/-1">
          <label>URL 列表（每行一个，自动补全 http:// 前缀；ip:端口 形式视为 TCP 目标，仅执行 network 协议 POC）</label>
          <textarea id="t-urls" placeholder="http://192.168.1.10:8080&#10;https://target.example.com&#10;192.168.1.20:6379（TCP 服务，如 Redis）"></textarea>
        </div>
        <div class="form-item"><label>备注名（可选）</label><input type="text" id="t-name" placeholder="如：测试环境"></div>
        <div class="form-item" style="justify-content:flex-end">
          <button class="btn btn-primary" id="t-add">＋ 添加并探活</button></div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">目标列表（${targets.length}）
        <div>
          <button class="btn btn-sm" id="t-probe-all">↻ 全部重新探活</button>
          <button class="btn btn-sm" id="t-probe-sel">↻ 探活所选</button>
          <button class="btn btn-sm btn-danger" id="t-del-sel">🗑 删除所选</button>
        </div>
      </div>
      <div class="table-wrap" style="border:none">
        <table>
          <thead><tr><th style="width:34px"><input type="checkbox" id="t-check-all" title="全选本页"></th><th>ID</th><th>状态</th><th>URL</th><th>备注</th><th>基线</th><th>RTT</th><th>错误</th><th></th></tr></thead>
          <tbody id="t-tbody"></tbody>
        </table>
      </div>
      <div id="t-pager-wrap"></div>
    </div>
    <div class="poc-sel-bar" id="t-sel-bar" style="display:none">
      <span>已选 <b id="t-sel-count">0</b> 个目标</span>
      <button class="btn btn-sm" id="t-sel-probe">↻ 探活所选</button>
      <button class="btn btn-sm btn-danger" id="t-sel-del">🗑 删除所选</button>
      <button class="btn btn-sm" id="t-sel-clear">清空选择</button>
    </div>`;

  const renderRows = () => {
    const start = (pager.page - 1) * pager.pageSize;
    const pageTargets = targets.slice(start, start + pager.pageSize);
    $('#t-tbody').innerHTML = pageTargets.map((t) => {
      const isTcp = !t.URL.includes('://');
      return `
      <tr>
        <td><input type="checkbox" class="t-check" value="${t.ID}" ${selTargets.has(t.ID) ? 'checked' : ''}></td>
        <td class="mono">${t.ID}</td>
        <td><span class="alive-dot ${t.Alive ? 'on' : 'off'}" title="${t.Alive ? '存活' : '不可达'}"></span> ${isTcp ? 'TCP ' : ''}${t.Alive ? '存活' : '不可达'}</td>
        <td class="mono ellipsis" style="max-width:320px" title="${esc(t.URL)}">${isTcp ? '<span class="badge badge-info" style="margin-right:4px">TCP</span>' : ''}${esc(t.URL)}</td>
        <td>${esc(t.Name || '-')}</td>
        <td class="mono">${isTcp ? '—' : (t.BaselineStatus || '-')}</td>
        <td class="mono">${t.BaselineRTTMS || 0}ms</td>
        <td class="ellipsis" style="max-width:180px;color:var(--red)" title="${esc(t.BaselineError)}">${esc(t.BaselineError || '')}</td>
        <td>
          <button class="btn btn-sm" onclick="probeTargets([${t.ID}])">探活</button>
          <button class="btn btn-sm btn-danger" onclick="removeTarget(${t.ID},'${esc(t.URL)}')">删除</button>
        </td>
      </tr>`;
    }).join('') || '<tr><td colspan="9" class="empty">暂无目标</td></tr>';
    $('#t-pager-wrap').innerHTML = pagerHTML('t', pager);
    bindPager('t', pager, () => renderRows());
    const boxes = [...document.querySelectorAll('#t-tbody .t-check')];
    $('#t-check-all').checked = boxes.length > 0 && boxes.every((c) => c.checked);
    updateSelBar();
  };
  const updateSelBar = () => {
    $('#t-sel-bar').style.display = selTargets.size > 0 ? 'flex' : 'none';
    $('#t-sel-count').textContent = selTargets.size;
  };

  $('#t-tbody').addEventListener('change', (e) => {
    const cb = e.target.closest('.t-check');
    if (!cb) return;
    cb.checked ? selTargets.add(Number(cb.value)) : selTargets.delete(Number(cb.value));
    const boxes = [...document.querySelectorAll('#t-tbody .t-check')];
    $('#t-check-all').checked = boxes.length > 0 && boxes.every((c) => c.checked);
    updateSelBar();
  });
  $('#t-check-all').addEventListener('change', (e) => {
    document.querySelectorAll('#t-tbody .t-check').forEach((c) => {
      c.checked = e.target.checked;
      e.target.checked ? selTargets.add(Number(c.value)) : selTargets.delete(Number(c.value));
    });
    updateSelBar();
  });
  $('#t-sel-clear').onclick = () => {
    selTargets.clear();
    document.querySelectorAll('#t-tbody .t-check').forEach((c) => { c.checked = false; });
    $('#t-check-all').checked = false;
    updateSelBar();
  };
  // 批量探活（顶栏按钮与底栏共用）
  const probeSel = async () => {
    if (!selTargets.size) { toast('请先勾选目标', 'error'); return; }
    await probeTargets([...selTargets]);
  };
  $('#t-probe-sel').onclick = probeSel;
  $('#t-sel-probe').onclick = probeSel;
  // 批量删除
  const delSel = async () => {
    const ids = [...selTargets];
    if (!ids.length) { toast('请先勾选目标', 'error'); return; }
    if (!confirmBox(`确认删除所选 ${ids.length} 个目标？`)) return;
    let ok = 0, fail = 0;
    for (const id of ids) {
      try { await API.del(`/targets/${id}`); ok++; }
      catch (e) { fail++; toast(`#${id} 删除失败：${e.message}`, 'error'); }
    }
    if (ok > 0) toast(`已删除 ${ok} 个目标${fail ? `（${fail} 个失败）` : ''}`, 'success');
    router();
  };
  $('#t-del-sel').onclick = delSel;
  $('#t-sel-del').onclick = delSel;

  $('#t-add').onclick = async () => {
    const urls = $('#t-urls').value.split('\n').map((s) => s.trim()).filter(Boolean);
    if (!urls.length) { toast('请输入至少一个 URL', 'error'); return; }
    try {
      const res = await API.post('/targets', { urls, name: $('#t-name').value.trim() });
      toast(`已添加 ${res.targets.length} 个目标`, 'success');
      router();
    } catch (e) { toast(e.message, 'error'); }
  };
  $('#t-probe-all').onclick = async (e) => {
    e.target.disabled = true; e.target.textContent = '探活中...';
    await probeTargets([]);
    e.target.disabled = false; e.target.textContent = '↻ 全部重新探活';
    router();
  };
  renderRows();
}

async function probeTargets(ids) {
  try {
    await API.post('/targets/probe', { ids });
    toast('探活完成', 'success');
    if (location.hash.startsWith('#/targets')) router();
  } catch (e) { toast(e.message, 'error'); }
}

async function removeTarget(id, url) {
  if (!confirmBox(`确认删除目标 ${url}？`)) return;
  try { await API.del(`/targets/${id}`); toast('已删除', 'success'); router(); }
  catch (e) { toast(e.message, 'error'); }
}

/* ============ 视图：发起攻击模拟 ============ */
async function renderScanNew(main) {
  const [targetsRes, statsRes, setsRes] = await Promise.all([
    apiGuard(() => API.get('/targets')),
    apiGuard(() => API.get('/pocs/stats')),
    apiGuard(() => API.get('/poc-sets')),
  ]);
  const targets = targetsRes.targets || [];
  const sets = setsRes.sets || [];
  // URL ?set=N 预选模板集（从模板集页跳转）
  const preSet = Number(new URLSearchParams(location.hash.split('?')[1] || '').get('set')) || 0;
  // POC 选取默认按模板集（无模板集时回退按条件筛选）
  const setModeDefault = sets.length > 0;

  main.innerHTML = `
    <div class="page-header">
      <div><div class="page-title">发起攻击模拟</div>
      <div class="page-desc">选取 POC 范围 × 目标 → 执行 → 实时查看 HIT / BLOCKED 判定</div></div>
    </div>

    <div class="card">
      <div class="card-title">① POC 选取
        <label style="font-size:12px;font-weight:normal;display:flex;gap:14px;align-items:center">
          <label><input type="radio" name="s-mode" value="filter" ${setModeDefault ? '' : 'checked'}> 按条件筛选</label>
          <label><input type="radio" name="s-mode" value="set" ${setModeDefault ? 'checked' : ''}> 按模板集</label>
        </label>
      </div>

      <div id="s-by-filter" style="display:${setModeDefault ? 'none' : ''}">
        <div class="form-grid">
          <div class="form-item"><label>扫描名称</label>
            <input type="text" id="s-name" placeholder="如：周一例行模拟"></div>
          <div class="form-item"><label>来源</label>
            <select id="s-source">
              <option value="">全部</option>
              <option value="custom">✎ 人工添加</option>
              <option value="official">★ 官方源</option>
              <option value="community">社区源</option>
            </select></div>
          <div class="form-item"><label>协议</label>
            <select id="s-protocol">
              <option value="">全部</option>
              ${['http', 'websocket', 'code', 'dns', 'network', 'ssl', 'headless', 'file', 'whois'].map((p) => `<option value="${p}">${p}</option>`).join('')}
            </select></div>
          <div class="form-item"><label>严重度</label>
            <select id="s-severity"><option value="">全部</option>
              ${['critical', 'high', 'medium', 'low', 'info'].map((s) => `<option value="${s}">${s}</option>`).join('')}
            </select></div>
          <div class="form-item"><label>标签</label>
            <input type="text" id="s-tag" placeholder="如 cve / rce"></div>
          <div class="form-item"><label>关键词</label>
            <input type="text" id="s-search" placeholder="模板ID / CVE 等"></div>
          <div class="form-item"><label>数量上限</label>
            <input type="number" id="s-max" placeholder="默认 ${statsRes.Total > 500 ? 500 : '全部（≤500）'}" min="1"></div>
        </div>
        <label class="checkbox-item" style="margin-top:10px">
          <input type="checkbox" id="s-nointer" checked> 排除 OOB 回连（Interactsh）模板
        </label>
      </div>

      <div id="s-by-set" style="display:${setModeDefault ? '' : 'none'}">
        <div class="form-grid">
          <div class="form-item"><label>选择模板集</label>
            <select id="s-set">
              <option value="">— 选择模板集 —</option>
              ${sets.map((s) => `<option value="${s.id}" ${preSet === s.id ? 'selected' : ''}>${esc(s.name)}（${s.poc_count} 个 POC）</option>`).join('')}
            </select>
          </div>
          <div class="form-item"><label>扫描名称</label>
            <input type="text" id="s-name2" placeholder="如：周一例行模拟"></div>
        </div>
        <div id="s-set-info" style="color:var(--muted);font-size:13px;margin-top:6px"></div>
        ${sets.length === 0 ? '<div class="empty" style="padding:14px">暂无模板集 —— 到 <a href="#/pocs" style="color:var(--accent)">POC 库</a> 勾选 POC 创建，或<a href="#/poc-sets" style="color:var(--accent)">管理模板集</a></div>' : ''}
      </div>

      <div style="margin-top:12px">
        <button class="btn" id="s-preview">🔍 预览匹配的 POC</button>
        <span id="s-preview-info" style="margin-left:10px;color:var(--muted);font-size:12px"></span>
      </div>
      <div id="s-preview-list" style="margin-top:10px"></div>
    </div>

    <div class="card">
      <div class="card-title">② 目标选择（${targets.length} 个）
        <div>
          <button class="btn btn-sm" id="s-sel-alive">只选存活</button>
          <button class="btn btn-sm" id="s-sel-all">全选</button>
          <button class="btn btn-sm" id="s-sel-none">清空</button>
        </div>
      </div>
      <div class="target-check-list">
        ${targets.map((t) => {
          const isTcp = !t.URL.includes('://');
          return `
          <label class="target-check-item ${t.Alive ? '' : 'dead'}" data-tid="${t.ID}">
            <input type="checkbox" class="t-check" value="${t.ID}" ${t.Alive ? 'checked' : ''}>
            <span class="alive-dot ${t.Alive ? 'on' : 'off'}"></span>
            <span class="url" title="${esc(t.URL)}">${isTcp ? '<span class="badge badge-info" style="margin-right:4px">TCP</span>' : ''}${esc(t.URL)}</span>
            <span class="mono" style="color:var(--muted);font-size:11px">${isTcp ? (t.Alive ? `TCP 存活 · ${t.BaselineRTTMS}ms` : '不可达') : (t.Alive ? `HTTP ${t.BaselineStatus} · ${t.BaselineRTTMS}ms` : '不可达')}</span>
          </label>`;
        }).join('') || '<div class="empty">暂无目标，请先 <a href="#/targets" style="color:var(--accent)">添加目标</a></div>'}
      </div>
      <label class="checkbox-item" style="margin-top:10px">
        <input type="checkbox" id="s-include-dead"> 包含不可达目标（结果将判为 UNREACHABLE，用于验证网络策略）
      </label>
    </div>

    <div class="card">
      <div class="card-title">③ 流量代理
        <span style="font-size:12px;color:var(--muted);font-weight:400">（攻击流量的出口，默认直连）</span>
      </div>
      <div class="form-grid">
        <div class="form-item"><label>代理模式</label>
          <select id="s-proxy-mode">
            <option value="direct" selected>🚫 直连（不走代理）</option>
            <option value="custom">🕳 自定义代理…</option>
          </select>
          <span class="hint">走代理时可指向 Burp / WAF 模拟代理，逐请求观察攻击 payload 与拦截行为</span></div>
        <div class="form-item" id="s-proxy-custom-item" style="display:none"><label>代理地址</label>
          <input type="text" id="s-proxy-custom" placeholder="http://127.0.0.1:8083">
          <span class="hint">支持 http / https / socks5，仅对本次扫描的攻击流量生效</span></div>
      </div>
    </div>

    <div class="card" style="text-align:center;padding:26px">
      <button class="btn btn-primary" id="s-launch" style="font-size:15px;padding:10px 42px">⚡ 启动攻击模拟</button>
      <div style="color:var(--muted);font-size:12px;margin-top:8px" id="s-summary">未选择 POC 与目标</div>
    </div>`;

  const selectedTargets = () => [...document.querySelectorAll('.t-check:checked')].map((c) => Number(c.value));
  const scanMode = () => document.querySelector('input[name="s-mode"]:checked')?.value || 'filter';

  // 模式切换
  document.querySelectorAll('input[name="s-mode"]').forEach((r) => {
    r.onchange = () => {
      $('#s-by-filter').style.display = scanMode() === 'filter' ? '' : 'none';
      $('#s-by-set').style.display = scanMode() === 'set' ? '' : 'none';
      updateSummary();
    };
  });

  // 模板集选中 → 显示概要
  const showSetInfo = async () => {
    const id = Number($('#s-set')?.value) || 0;
    if (!id) { $('#s-set-info').textContent = ''; return; }
    try {
      const d = await API.get(`/poc-sets/${id}`);
      const pocs = d.pocs || [];
      const bySev = {};
      pocs.forEach((p) => { bySev[p.Severity] = (bySev[p.Severity] || 0) + 1; });
      const sevText = Object.entries(bySev).map(([k, v]) => `${k} ${v}`).join(' · ') || '空';
      $('#s-set-info').textContent = `共 ${pocs.length} 个 POC（${sevText}）`;
    } catch (e) { $('#s-set-info').textContent = ''; }
  };
  $('#s-set')?.addEventListener('change', showSetInfo);
  if (preSet) showSetInfo();

  const previewFilter = () => {
    if (scanMode() === 'set') {
      return { set_id: Number($('#s-set')?.value) || 0, severity: '', tag: '', search: '', no_interactsh: false, limit: 0 };
    }
    const src = decodeSource($('#s-source').value);
    return {
      official: src.official,
      custom: src.custom,
      protocol: $('#s-protocol').value,
      severity: $('#s-severity').value,
      tag: $('#s-tag').value.trim(),
      search: $('#s-search').value.trim(),
      no_interactsh: $('#s-nointer').checked,
      limit: Number($('#s-max').value) || 0,
    };
  };

  const updateSummary = () => {
    const n = selectedTargets().length;
    const info = $('#s-preview-info').textContent;
    $('#s-summary').textContent = `${info || '未预览 POC'} · 已选目标 ${n} 个`;
  };

  $('#s-preview').onclick = async () => {
    const el = $('#s-preview-list');
    el.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    const f = previewFilter();
    if (scanMode() === 'set') {
      if (!f.set_id) { toast('请先选择模板集', 'error'); el.innerHTML = ''; return; }
    }
    const q = new URLSearchParams({ ...f, limit: '20', no_interactsh: f.no_interactsh ? 'true' : '' });
    try {
      const data = await API.get('/pocs?' + q.toString());
      const total = data.total || 0;
      $('#s-preview-info').textContent = `匹配 ${total} 个 POC（预览前 20）`;
      el.innerHTML = total === 0
        ? '<div class="empty" style="padding:16px">无匹配 POC</div>'
        : `<div class="table-wrap"><table>
            <thead><tr><th>模板 ID</th><th>名称</th><th>严重度</th><th>标签</th></tr></thead>
            <tbody>${(data.pocs || []).map((p) => `
              <tr class="result-row">
                <td class="mono">${esc(p.TemplateID)}</td>
                <td class="ellipsis">${esc(p.Name)}</td>
                <td>${severityBadge(p.Severity)}</td>
                <td class="mono">${esc(p.Tags.replace(/,/g, ' ').trim())}</td>
              </tr>`).join('')}
            </tbody></table></div>`;
      updateSummary();
    } catch (e) { toast(e.message, 'error'); el.innerHTML = ''; }
  };

  document.querySelectorAll('.t-check').forEach((c) => c.addEventListener('change', updateSummary));
  $('#s-sel-alive').onclick = () => {
    document.querySelectorAll('.target-check-item').forEach((item) => {
      item.querySelector('.t-check').checked = item.querySelector('.alive-dot').classList.contains('on');
    });
    updateSummary();
  };
  $('#s-sel-all').onclick = () => { document.querySelectorAll('.t-check').forEach((c) => (c.checked = true)); updateSummary(); };
  $('#s-sel-none').onclick = () => { document.querySelectorAll('.t-check').forEach((c) => (c.checked = false)); updateSummary(); };

  // 流量代理：自定义时显示地址输入框
  $('#s-proxy-mode').onchange = (e) => {
    $('#s-proxy-custom-item').style.display = e.target.value === 'custom' ? '' : 'none';
  };
  // 当前生效的代理地址（空 = 直连）
  const scanProxy = () => ($('#s-proxy-mode')?.value === 'custom' ? ($('#s-proxy-custom')?.value.trim() || '') : '');
  updateSummary();

  $('#s-launch').onclick = async () => {
    const targetIDs = selectedTargets();
    if (!targetIDs.length) { toast('请至少选择一个目标', 'error'); return; }
    const proxy = scanProxy();
    if ($('#s-proxy-mode').value === 'custom' && !proxy) { toast('请输入代理地址，或改选直连', 'error'); return; }
    const f = previewFilter();
    const nameInput = scanMode() === 'set' ? $('#s-name2') : $('#s-name');
    const body = {
      name: (nameInput?.value.trim() || '') || `模拟-${new Date().toLocaleString('zh-CN')}`,
      target_ids: targetIDs,
      official: f.official || '',
      custom: f.custom || '',
      protocol: f.protocol || '',
      severity: f.severity,
      tag: f.tag,
      search: f.search,
      max: f.limit,
      poc_set_id: f.set_id || 0,
      no_interactsh: scanMode() === 'filter' ? $('#s-nointer').checked : false,
      include_dead: $('#s-include-dead').checked,
      proxy,
    };
    if (scanMode() === 'set' && !body.poc_set_id) { toast('请先选择模板集', 'error'); return; }
    try {
      const res = await API.post('/scans', body);
      toast(`扫描 #${res.scan_id} 已启动`, 'success');
      location.hash = `#/scans/${res.scan_id}`;
    } catch (e) { toast(e.message, 'error'); }
  };
}

/* ============ 视图：扫描历史 ============ */
async function renderScans(main) {
  // 后端分页
  const pager = { page: 1, pageSize: 20, total: 0 };
  const sel = new Set(); // 已勾选的扫描 ID

  // 排序：勾选态持有扫描名称（删除确认用）；列表按行渲染
  const rowHTML = (sc) => `
    <tr class="clickable" data-sid="${sc.ID}" onclick="location.hash='#/scans/${sc.ID}'">
      <td>${sc.Status !== 'running'
        ? `<input type="checkbox" class="sc-sel" data-sid="${sc.ID}" onclick="event.stopPropagation()" ${sel.has(sc.ID) ? 'checked' : ''}>`
        : '<input type="checkbox" disabled title="运行中的扫描不可删除">'}</td>
      <td class="mono">#${sc.ID}</td>
      <td class="ellipsis">${esc(sc.Name || '-')}</td>
      <td>${statusBadge(sc.Status)}</td>
      <td class="mono">${sc.TargetCount}×${sc.POCCount}</td>
      <td class="mono" style="color:${sc.HitCount ? 'var(--red)' : 'inherit'}">${sc.HitCount}</td>
      <td class="mono" style="color:${sc.BlockedCount ? 'var(--orange)' : 'inherit'}">${sc.BlockedCount}</td>
      <td class="mono">${sc.TimeoutCount}</td>
      <td class="mono">${sc.MissCount}</td>
      <td class="mono">${fmtTime(sc.StartedAt)}</td>
      <td style="white-space:nowrap">
        <button class="btn btn-sm" onclick="event.stopPropagation();location.hash='#/scans/${sc.ID}'">详情</button>
        ${sc.Status !== 'running' ? `<button class="btn btn-sm btn-danger" title="删除该扫描及其结果与流量" onclick="event.stopPropagation();deleteScan(${sc.ID}, '${esc(sc.Name || '')}')">🗑</button>` : ''}
      </td>
    </tr>`;

  main.innerHTML = `
    <div class="page-header">
      <div><div class="page-title">扫描历史</div><div class="page-desc">全部攻击模拟任务</div></div>
      <div class="header-actions"><a class="btn btn-primary" href="#/scan/new">⚡ 新建扫描</a></div>
    </div>
    <div class="card">
      <div class="table-wrap" style="border:none">
        <table>
          <thead><tr><th style="width:34px"><input type="checkbox" id="sc-sel-all" title="全选（仅可删除项）"></th><th>ID</th><th>名称</th><th>状态</th><th>目标/POC</th><th>HIT</th><th>BLOCK</th><th>TIMEOUT</th><th>MISS</th><th>开始时间</th><th></th></tr></thead>
          <tbody id="sc-tbody"></tbody>
        </table>
      </div>
      <div id="sc-pager-wrap"></div>
    </div>
    <div class="poc-sel-bar" id="sc-sel-bar" style="display:none">
      已勾选 <b id="sc-sel-count">0</b> 个扫描
      <button class="btn btn-sm btn-danger" id="sc-del-batch">🗑 删除所选</button>
      <button class="btn btn-sm" id="sc-sel-clear">取消勾选</button>
    </div>`;

  const bar = $('#sc-sel-bar');
  const syncBar = () => {
    $('#sc-sel-count').textContent = sel.size;
    bar.style.display = sel.size ? 'flex' : 'none';
  };
  const syncAll = () => {
    const boxes = [...document.querySelectorAll('#sc-tbody .sc-sel')];
    $('#sc-sel-all').checked = boxes.every((b) => b.checked);
    // 全选框禁用态：本页无勾选项时禁用
    $('#sc-sel-all').disabled = boxes.length === 0;
    syncBar();
  };

  const load = async () => {
    const q = new URLSearchParams({ limit: String(pager.pageSize), offset: String((pager.page - 1) * pager.pageSize) });
    try {
      const data = await apiGuard(() => API.get('/scans?' + q.toString()));
      const scans = data.scans || [];
      pager.total = data.total || pager.total;
      $('#sc-tbody').innerHTML = scans.map(rowHTML).join('')
        || '<tr><td colspan="11" class="empty">暂无扫描</td></tr>';
      $('#sc-pager-wrap').innerHTML = pagerHTML('sc', pager);
      bindPager('sc', pager, () => load());
      syncAll();
    } catch (e) { /* apiGuard 已 toast */ }
  };

  // 行勾选 / 取消
  $('#sc-tbody').addEventListener('change', (e) => {
    const b = e.target.closest('.sc-sel');
    if (!b) return;
    const sid = Number(b.dataset.sid);
    if (b.checked) sel.add(sid); else sel.delete(sid);
    syncAll();
  });
  // 全选 / 取消全选（仅可删除项）
  $('#sc-sel-all').addEventListener('change', (e) => {
    document.querySelectorAll('#sc-tbody .sc-sel').forEach((b) => {
      b.checked = e.target.checked;
      const sid = Number(b.dataset.sid);
      if (b.checked) sel.add(sid); else sel.delete(sid);
    });
    syncBar();
  });
  $('#sc-sel-clear').onclick = () => {
    sel.clear();
    document.querySelectorAll('#sc-tbody .sc-sel').forEach((b) => { b.checked = false; });
    $('#sc-sel-all').checked = false;
    syncBar();
  };
  $('#sc-del-batch').onclick = async () => {
    const ids = [...sel];
    if (!ids.length) return;
    await deleteScans(ids);
  };
  await load();
}

/* 批量删除扫描历史：逐个删除，容忍单项失败（如并发被删/状态变化） */
async function deleteScans(ids) {
  if (!confirmBox(`确认删除所选 ${ids.length} 个扫描？\n其结果与流量记录将一并删除，不可恢复。`)) return;
  let ok = 0, fail = 0;
  for (const id of ids) {
    try { await API.del(`/scans/${id}`); ok++; }
    catch (e) { fail++; toast(`#${id} 删除失败：${e.message}`, 'error'); }
  }
  if (ok > 0) toast(`已删除 ${ok} 个扫描${fail ? `（${fail} 个失败）` : ''}`, 'success');
  router(); // 重新渲染列表（清空勾选状态）
}

/* 删除扫描历史（含结果与流量级联删除） */
async function deleteScan(id, name) {
  if (!confirmBox(`确认删除扫描 #${id}「${name}」？\n其结果与流量记录将一并删除，不可恢复。`)) return;
  try {
    await API.del(`/scans/${id}`);
    toast(`扫描 #${id} 已删除`, 'success');
    // 详情页删除 → 回列表；列表页删除 → 刷新（hash 不变时手动触发）
    if (location.hash.startsWith(`#/scans/${id}`)) location.hash = '#/scans';
    else router();
  } catch (e) { toast(e.message, 'error'); }
}

/* ============ 视图：扫描详情（SSE 实时） ============ */
async function renderScanDetail(main, params) {
  const id = params.id;
  let scan;
  try { scan = await API.get(`/scans/${id}`); }
  catch (e) {
    main.innerHTML = `<div class="empty"><div class="empty-icon">🔍</div><div>扫描 #${esc(id)} 不存在</div></div>`;
    return;
  }

  const running = scan.Status === 'running';
  // 任务流量/镜像连接分页状态（模板中引用，需先定义）
  const trafficPage = { offset: 0, limit: 50, total: -1 };
  const dumpPage = { offset: 0, limit: 50, total: -1 };
  main.innerHTML = `
    <div class="page-header">
      <div><div class="page-title">扫描 #${scan.ID} · ${esc(scan.Name || '')}</div>
        <div class="page-desc">目标 ${scan.TargetCount} × POC ${scan.POCCount} · ${fmtTime(scan.StartedAt)}${scan.FinishedAt ? ' → ' + fmtTime(scan.FinishedAt) : ''}</div></div>
      <div class="header-actions">
        <button class="btn" id="d-refresh">↻ 刷新</button>
        <a class="btn" href="/api/v1/scans/${id}/report?format=md" target="_blank">📄 MD</a>
        <a class="btn" href="/api/v1/scans/${id}/report?format=json" target="_blank">JSON</a>
        <a class="btn" href="/api/v1/scans/${id}/report?format=csv" target="_blank">CSV</a>
        ${running ? '<button class="btn btn-danger" id="d-cancel">■ 取消</button>'
          : `<button class="btn btn-danger" id="d-delete" title="删除该扫描及其结果与流量">🗑 删除</button>`}
      </div>
    </div>

    <div class="page-tabs" id="d-page-tabs">
      <button class="page-tab active" data-tab="overview">📊 概览</button>
      <button class="page-tab" data-tab="results">📋 结果明细${running ? ' <span style="color:var(--green);font-size:11px">●</span>' : ''}</button>
      <button class="page-tab" data-tab="traffic">📦 任务流量</button>
      <button class="page-tab" data-tab="dump">🔗 镜像连接</button>
    </div>

    <div id="d-tab-overview">
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div>${statusBadge(scan.Status)} <span id="d-live-badge" style="font-size:11px;color:${running ? 'var(--green)' : 'var(--muted)'}">${running ? '● LIVE' : '■ 已结束'}</span>
            <span id="d-status-extra" style="color:var(--muted);font-size:12px;margin-left:8px"></span></div>
          <div style="font-size:12px;color:var(--muted)" title="本次扫描攻击流量的出口（发起时选择，不影响探活）">
            ${scan.Proxy ? `🕳 经代理 <span class="mono" style="color:var(--accent)">${esc(scan.Proxy)}</span>` : '🚫 直连'}
          </div>
        </div>
        ${scan.ErrorText ? `<div style="margin-top:10px;padding:10px 14px;border-radius:8px;background:rgba(255,77,79,.12);border:1px solid rgba(255,77,79,.4);color:#ff9a9c;font-size:13px">
          ⚠ ${esc(scan.ErrorText)}${scan.ErrorCount > 0 ? `（${scan.ErrorCount} 个任务判为 ERROR，见结果明细）` : ''}
        </div>` : ''}
        <div class="progress-wrap">
          <div class="progress-info"><span id="d-prog-text">0 / ${scan.TotalTasks}</span><span id="d-prog-pct">0%</span></div>
          <div class="progress-bar"><div class="progress-fill" id="d-prog-fill"></div></div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">判定矩阵 <span style="font-size:12px;color:var(--muted);font-weight:400">（点击卡片跳转结果明细对应类别）</span></div>
        <div class="scan-verdict-grid">
          ${[['HIT', '漏洞命中', scan.HitCount], ['BLOCKED', '被防御拦截', scan.BlockedCount],
             ['TIMEOUT', '攻击超时', scan.TimeoutCount], ['UNREACHABLE', '目标不可达', scan.UnreachableCount],
             ['MISS', '未命中', scan.MissCount], ['ERROR', '执行错误', scan.ErrorCount]]
            .map(([v, label, n]) => `
              <div class="verdict-tile v-${v} ${n ? '' : 'zero'}" data-verdict-tile="${v}" title="点击查看 ${v} 结果明细" style="cursor:pointer">
                <div class="num" id="d-num-${v}">${n}</div><div class="lbl">${label}</div>
              </div>`).join('')}
        </div>
      </div>
    </div>

    <div id="d-tab-results" style="display:none">
      <div class="card">
        <div class="card-title">结果明细
          <span style="font-size:12px;color:var(--muted);font-weight:400">（判定徽章可点击人工修正；✎ = 人工修正过；🛡 = 流量含特征）</span></div>
        <div class="verdict-tabs" id="d-tabs">
          <button class="verdict-tab active" data-v="">全部</button>
          ${['HIT', 'BLOCKED', 'TIMEOUT', 'UNREACHABLE', 'MISS', 'ERROR'].map((v) =>
            `<button class="verdict-tab" data-v="${v}">${v}</button>`).join('')}
        </div>
        ${!running ? `
        <div class="feat-bar">
          <span class="feat-title" title="搜索全部任务的请求/响应包内容，定位含特定特征（如 WAF 拦截页指纹、Server 头）的结果行，配合勾选批量修正判定">🛡 流量特征搜索</span>
          <input type="text" id="d-feat-kw" placeholder="包内容特征（如 WAF 拦截页指纹、Server 头、状态行…），命中行可批量打标签">
          <select id="d-feat-field" title="搜索范围">
            <option value="">请求+响应</option>
            <option value="request">仅请求包</option>
            <option value="response">仅响应包</option>
          </select>
          <button class="btn btn-sm" id="d-feat-btn">🔍 搜索</button>
          <button class="btn btn-sm" id="d-feat-clear" style="display:none">清除</button>
        </div>
        <div class="feat-info" id="d-feat-info" style="display:none">
          <label style="cursor:pointer;display:flex;align-items:center;gap:4px">
            <input type="checkbox" id="d-feat-only"> 仅显示命中行
          </label>
          <span id="d-feat-stat"></span>
          <button class="btn btn-sm" id="d-feat-select-all">✓ 全选命中行</button>
          <span style="color:var(--muted)">→ 在下方批量修正中选「选中项」或「🛡 特征命中项」</span>
        </div>
        <div class="batch-bar">
          <span style="font-size:12px;color:var(--muted)">批量修正：</span>
          <button class="btn btn-sm" id="d-batch-sel">✓ 选中项</button>
          <button class="btn btn-sm" id="d-batch-cat" title="将当前过滤类别下的全部结果改为目标判定">当前类别全部</button>
          <button class="btn btn-sm" id="d-batch-feat" style="display:none" title="将流量含特征的全部结果改为目标判定">🛡 特征命中项</button>
          <span style="font-size:12px;color:var(--muted)">→ 改为</span>
          <select id="d-batch-verdict">
            ${['HIT', 'BLOCKED', 'TIMEOUT', 'UNREACHABLE', 'MISS', 'ERROR'].map((v) => `<option value="${v}">${v}</option>`).join('')}
            <option value="">（恢复自动判定）</option>
          </select>
          <span id="d-batch-count" style="font-size:12px;color:var(--muted)"></span>
        </div>` : ''}
        <div class="live-results">
          <div class="table-wrap" style="border:none">
            <table>
              <thead><tr>${!running ? '<th style="width:28px"><input type="checkbox" id="d-sel-all" title="全选当前页"></th>' : ''}<th>判定</th><th>模板</th><th>严重度</th><th>目标</th><th>HTTP</th><th>错误</th><th>特征</th><th>包</th></tr></thead>
              <tbody id="d-results"></tbody>
            </table>
          </div>
          <div id="d-results-pager"></div>
        </div>
      </div>
    </div>

    <div id="d-tab-traffic" style="display:none">
      <div class="card">
        <div class="card-title">任务流量 <span style="font-size:12px;color:var(--muted);font-weight:400">（全部任务按事件顺序的请求/响应包流水；特征搜索请用「结果明细」页签）</span></div>
        <div class="table-wrap" style="border:none">
          <table>
            <thead><tr><th>SEQ</th><th>协议</th><th>匹配</th><th>HTTP</th><th>模板</th><th>目标</th><th>大小</th><th></th></tr></thead>
            <tbody id="d-traffic"></tbody>
          </table>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px">
          <span id="d-traffic-info" style="color:var(--muted);font-size:12px"></span>
          <div style="display:flex;gap:8px;align-items:center">
            <label class="page-size">每页
              <select class="page-size-select" id="d-traffic-size">
                ${PAGE_SIZES.map((n) => `<option value="${n}" ${trafficPage.limit === n ? 'selected' : ''}>${n}</option>`).join('')}
              </select> 条</label>
            <button class="btn btn-sm" id="d-traffic-prev">← 上一页</button>
            <button class="btn btn-sm" id="d-traffic-next">下一页 →</button>
          </div>
        </div>
      </div>
    </div>

    <div id="d-tab-dump" style="display:none">
      <div class="card">
        <div class="card-title">镜像连接流水
          <span style="font-size:12px;color:var(--muted);font-weight:400">（socks5 镜像代理在传输层逐连接记录的双向字节流；fuzz 字典、多请求攻击链的全部中间请求在这里完整可见，与「任务流量」的事件级最终请求互补）</span>
        </div>
        <div class="table-wrap" style="border:none">
          <table>
            <thead><tr><th>SEQ</th><th>连接目标</th><th>耗时</th><th>客户端→服务端</th><th>服务端→客户端</th><th></th></tr></thead>
            <tbody id="d-dump"></tbody>
          </table>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px">
          <span id="d-dump-info" style="color:var(--muted);font-size:12px"></span>
          <div style="display:flex;gap:8px;align-items:center">
            <label class="page-size">每页
              <select class="page-size-select" id="d-dump-size">
                ${PAGE_SIZES.map((n) => `<option value="${n}" ${dumpPage.limit === n ? 'selected' : ''}>${n}</option>`).join('')}
              </select> 条</label>
            <button class="btn btn-sm" id="d-dump-prev">← 上一页</button>
            <button class="btn btn-sm" id="d-dump-next">下一页 →</button>
          </div>
        </div>
      </div>
    </div>`;

  const resultsEl = $('#d-results');
  const rows = [];
  let verdictFilter = '';
  const editable = !running; // 运行中禁止人工修正（结果仍在写入）
  const selected = new Set(); // 勾选的结果行 ID

  // 流量特征搜索状态：trafficHits 为命中特征的任务键集合（"pocID:targetID"）
  const trafficHits = new Set();
  let trafficKw = '';
  let trafficOnly = false;
  const hitKey = (r) => `${r.POCID || 0}:${r.TargetID || 0}`;
  const isHit = (r) => !!trafficKw && trafficHits.has(hitKey(r));

  // 页面级 Tab 切换（概览 / 结果明细 / 任务流量 / 镜像连接）
  const switchTab = (name, focusVerdict) => {
    document.querySelectorAll('#d-page-tabs .page-tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
    ['overview', 'results', 'traffic', 'dump'].forEach((n) => {
      const el = $(`#d-tab-${n}`);
      if (el) el.style.display = n === name ? '' : 'none';
    });
    if (focusVerdict !== undefined) {
      document.querySelectorAll('.verdict-tab').forEach((b) => b.classList.remove('active'));
      const btn = $(`#d-tabs .verdict-tab[data-v="${focusVerdict}"]`);
      if (btn) btn.classList.add('active');
      verdictFilter = focusVerdict;
      renderRows();
    }
  };
  $('#d-page-tabs').addEventListener('click', (e) => {
    const btn = e.target.closest('.page-tab');
    if (btn) switchTab(btn.dataset.tab);
  });
  // 判定矩阵 tile 点击 → 结果明细页签 + 按类别过滤
  document.querySelectorAll('[data-verdict-tile]').forEach((tile) => {
    tile.addEventListener('click', () => switchTab('results', tile.dataset.verdictTile));
  });

  // manualBadge 人工修正标记（✎ + hover 展示原判定与修改时间）。
  const manualBadge = (r) => {
    if (!r.ManualAt && !r.manual_at) return '';
    const auto = r.AutoVerdict || r.auto_verdict || '?';
    const at = fmtTime(r.ManualAt || r.manual_at);
    return ` <span style="cursor:help" title="人工修正于 ${esc(at)}（机器判定：${esc(auto)}）">✎</span>`;
  };

  // verdictCell 判定单元格：非运行中可点击弹出修正菜单。
  const verdictCell = (r) => {
    const v = r.Verdict || r.verdict;
    if (!editable) return verdictBadge(v);
    return `<span class="verdict verdict-${esc(v)} verdict-edit" style="cursor:pointer" title="点击人工修正判定"
      onclick="showVerdictPicker(${id}, ${r.ID})">${esc(v)}</span>${manualBadge(r)}`;
  };

  const resultRow = (r) => `
    <tr class="result-row ${isHit(r) ? 'row-hit' : ''}" data-rid="${r.ID}">
      ${editable ? `<td><input type="checkbox" class="d-row-sel" data-rid="${r.ID}"></td>` : ''}
      <td>${verdictCell(r)}</td>
      <td class="mono ellipsis" title="${esc(r.TemplateID)}">${esc(r.TemplateID)}</td>
      <td>${severityBadge(r.Severity)}</td>
      <td class="mono ellipsis" style="max-width:260px" title="${esc(r.TargetURL)}">${esc(r.TargetURL)}</td>
      <td class="mono">${r.ResponseStatus || '-'}</td>
      <td class="ellipsis" style="max-width:180px;color:var(--red)">${esc(r.ErrorText || '')}</td>
      <td>${isHit(r) ? `<span class="feat-hit" title="流量包含特征「${esc(trafficKw)}」">🛡</span>` : '<span style="color:var(--border-light)">—</span>'}</td>
      <td><button class="btn btn-sm" title="查看该任务发送的请求/响应包" onclick="showTrafficModal(${id}, ${r.POCID || 0}, ${r.TargetID || 0})">📦</button></td>
    </tr>`;

  // visibleRows 当前可见行 = 类别 tab 过滤 + 「仅显示命中行」过滤
  const visibleRows = () => {
    let list = rows;
    if (verdictFilter) list = list.filter((r) => r.Verdict === verdictFilter);
    if (trafficOnly && trafficKw) list = list.filter(isHit);
    return list;
  };

  // 结果明细分页（本地分页：rows 全量在内存，仅渲染当前页）
  const resPager = { page: 1, pageSize: 50, total: 0 };
  const clampResPage = () => {
    const pages = Math.max(1, Math.ceil(resPager.total / resPager.pageSize));
    if (resPager.page > pages) resPager.page = pages;
    if (resPager.page < 1) resPager.page = 1;
  };

  const renderRows = () => {
    const filtered = visibleRows();
    resPager.total = filtered.length;
    clampResPage();
    const start = (resPager.page - 1) * resPager.pageSize;
    const pageItems = filtered.slice(start, start + resPager.pageSize);
    resultsEl.innerHTML = pageItems.map(resultRow).join('')
      || `<tr><td colspan="${editable ? 9 : 8}" class="empty">${trafficOnly && trafficKw ? '当前过滤条件下无命中行' : '暂无结果'}</td></tr>`;
    // 恢复勾选状态
    resultsEl.querySelectorAll('.d-row-sel').forEach((cb) => { cb.checked = selected.has(Number(cb.dataset.rid)); });
    // 分页条（结果只读时也显示，便于浏览）
    $('#d-results-pager').innerHTML = pagerHTML('dres', resPager);
    bindPager('dres', resPager, () => renderRows());
    updateSelCount();
    updateFeatStat();
  };

  // 勾选事件（事件委托）与全选
  resultsEl.addEventListener('change', (e) => {
    const cb = e.target.closest('.d-row-sel');
    if (!cb) return;
    const rid = Number(cb.dataset.rid);
    cb.checked ? selected.add(rid) : selected.delete(rid);
    updateSelCount();
  });
  $('#d-sel-all')?.addEventListener('change', (e) => {
    // 全选仅作用于当前页（跨页勾选由 selected 集合保留，顶部批量操作据此执行）
    const start = (resPager.page - 1) * resPager.pageSize;
    const pageItems = visibleRows().slice(start, start + resPager.pageSize);
    pageItems.forEach((r) => { if (r.ID) e.target.checked ? selected.add(r.ID) : selected.delete(r.ID); });
    renderRows();
  });

  const updateSelCount = () => {
    const el = $('#d-batch-count');
    if (!el) return;
    el.textContent = selected.size ? `已选 ${selected.size} 条` : '';
  };

  // 人工修正判定：调 API 后刷新结果与判定矩阵计数。
  const applyVerdicts = async (body, desc) => {
    try {
      const d = await API.post(`/scans/${id}/results/verdict`, body);
      toast(`已修正 ${d.updated} 条结果${desc ? `（${desc}）` : ''}`, 'success');
      await reloadResults();
    } catch (e) { toast(e.message, 'error'); }
  };

  // reloadResults 重新拉取结果明细与扫描计数（判定矩阵同步）。
  const reloadResults = async () => {
    try {
      const d = await API.get(`/scans/${id}/results`);
      rows.length = 0;
      (d.results || []).forEach((r) => rows.push(r));
      renderRows();
      // 刷新判定矩阵计数
      const s = await API.get(`/scans/${id}`);
      [['HIT', s.HitCount], ['BLOCKED', s.BlockedCount], ['TIMEOUT', s.TimeoutCount],
       ['UNREACHABLE', s.UnreachableCount], ['MISS', s.MissCount], ['ERROR', s.ErrorCount]]
        .forEach(([v, n]) => {
          const numEl = $(`#d-num-${v}`);
          const tile = $(`[data-verdict-tile="${v}"]`);
          if (numEl) numEl.textContent = n;
          if (tile) tile.classList.toggle('zero', !n);
        });
      setProgress(s.DoneTasks, s.TotalTasks);
    } catch (e) { /* 忽略 */ }
  };

  // 流量特征搜索：遍历 traffic API 分页拿全量命中（poc,target）组合，
  // 结果行标记 🛡；配合「仅显示命中行」与批量修正实现按特征批量打标签。
  const updateFeatStat = () => {
    const el = $('#d-feat-stat');
    if (!el) return;
    if (!trafficKw) { el.textContent = ''; return; }
    el.textContent = `特征「${trafficKw}」命中 ${rows.filter(isHit).length} / ${rows.length} 条结果`;
  };

  const updateFeatUI = () => {
    const hasKw = !!trafficKw;
    const info = $('#d-feat-info');
    const clearBtn = $('#d-feat-clear');
    const batchFeat = $('#d-batch-feat');
    if (info) info.style.display = hasKw ? 'flex' : 'none';
    if (clearBtn) clearBtn.style.display = hasKw ? '' : 'none';
    if (batchFeat) batchFeat.style.display = hasKw ? '' : 'none';
    updateFeatStat();
  };

  const doFeatSearch = async () => {
    const kw = ($('#d-feat-kw')?.value || '').trim();
    trafficKw = kw;
    trafficHits.clear();
    trafficOnly = false;
    if ($('#d-feat-only')) $('#d-feat-only').checked = false;
    if (!kw) { updateFeatUI(); renderRows(); return; }
    const field = $('#d-feat-field')?.value || '';
    let offset = 0, total = Infinity, guard = 0;
    try {
      while (offset < total && guard++ < 50) {
        const params = new URLSearchParams({ search: kw, limit: 10000, offset: String(offset) });
        if (field) params.set('field', field);
        const d = await API.get(`/scans/${id}/traffic?` + params.toString());
        total = d.total || 0;
        const list = d.traffic || [];
        list.forEach((t) => trafficHits.add(`${t.POCID}:${t.TargetID}`));
        if (!list.length) break;
        offset += list.length;
      }
      toast(`特征「${kw}」命中 ${trafficHits.size} 个任务`, 'success');
    } catch (e) {
      toast('特征搜索失败：' + e.message, 'error');
      trafficKw = '';
      trafficHits.clear();
    }
    updateFeatUI();
    renderRows();
  };
  $('#d-feat-btn')?.addEventListener('click', doFeatSearch);
  $('#d-feat-kw')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') doFeatSearch(); });
  $('#d-feat-clear')?.addEventListener('click', () => {
    if ($('#d-feat-kw')) $('#d-feat-kw').value = '';
    trafficKw = '';
    trafficHits.clear();
    trafficOnly = false;
    if ($('#d-feat-only')) $('#d-feat-only').checked = false;
    updateFeatUI();
    renderRows();
  });
  $('#d-feat-only')?.addEventListener('change', (e) => {
    trafficOnly = e.target.checked;
    renderRows();
  });
  $('#d-feat-select-all')?.addEventListener('click', () => {
    const hits = rows.filter((r) => isHit(r) && r.ID);
    if (!hits.length) { toast('当前无特征命中行', 'error'); return; }
    hits.forEach((r) => selected.add(r.ID));
    renderRows();
    toast(`已勾选 ${hits.length} 条特征命中行`, 'success');
  });

  // 单条修正菜单（行内下拉）
  window.showVerdictPicker = (scanID, resultID) => {
    const opts = ['HIT', 'BLOCKED', 'TIMEOUT', 'UNREACHABLE', 'MISS', 'ERROR'].map((v) =>
      `<button class="btn btn-sm" style="display:block;width:100%;margin:2px 0" data-v="${v}">${v}</button>`).join('');
    $('#modal-root').innerHTML = `
      <div class="modal-overlay" onclick="if(event.target===this)closeModal()">
        <div class="modal" style="max-width:280px">
          <div class="modal-header"><h3>✎ 人工修正判定 #${resultID}</h3><button class="modal-close" onclick="closeModal()">×</button></div>
          <div class="modal-body">
            <div style="font-size:12px;color:var(--muted);margin-bottom:8px">机器自动判定可能不准（WAF 指纹误判等），可先查看流量包特征再修正：</div>
            ${opts}
            <button class="btn btn-sm" style="display:block;width:100%;margin:6px 0 0" data-v="">↺ 恢复机器判定</button>
          </div>
        </div>
      </div>`;
    $('#modal-root .modal-body').addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-v]');
      if (!btn) return;
      closeModal();
      await applyVerdicts({ result_ids: [resultID], to_verdict: btn.dataset.v },
        btn.dataset.v ? `改为 ${btn.dataset.v}` : '恢复机器判定');
    });
  };

  // 批量修正：选中项
  $('#d-batch-sel')?.addEventListener('click', async () => {
    if (!selected.size) { toast('请先勾选结果行', 'error'); return; }
    const to = $('#d-batch-verdict').value;
    if (!confirmBox(`确认将选中的 ${selected.size} 条结果${to ? `改为 ${to}` : '恢复机器自动判定'}？`)) return;
    await applyVerdicts({ result_ids: [...selected], to_verdict: to }, `选中 ${selected.size} 条`);
    selected.clear();
  });

  // 批量修正：当前类别全部（需先选定类别 tab）
  $('#d-batch-cat')?.addEventListener('click', async () => {
    if (!verdictFilter) { toast('请先在上方判定页签选定类别（如 BLOCKED）', 'error'); return; }
    const n = rows.filter((r) => r.Verdict === verdictFilter).length;
    if (!n) { toast('当前类别下无结果', 'error'); return; }
    const to = $('#d-batch-verdict').value;
    if (!confirmBox(`确认将全部 ${n} 条 ${verdictFilter} 结果${to ? `改为 ${to}` : '恢复机器自动判定'}？`)) return;
    await applyVerdicts({ from_verdict: verdictFilter, to_verdict: to }, `${verdictFilter} × ${n} 条`);
  });

  // 批量修正：特征命中项（流量包含搜索特征的全部结果，与当前类别过滤无关）
  $('#d-batch-feat')?.addEventListener('click', async () => {
    const ids = rows.filter((r) => isHit(r) && r.ID).map((r) => r.ID);
    if (!ids.length) { toast('当前无特征命中行', 'error'); return; }
    const to = $('#d-batch-verdict').value;
    if (!confirmBox(`确认将流量含特征「${trafficKw}」的 ${ids.length} 条结果${to ? `改为 ${to}` : '恢复机器自动判定'}？`)) return;
    await applyVerdicts({ result_ids: ids, to_verdict: to }, `特征命中 ${ids.length} 条`);
  });

  $('#d-tabs').addEventListener('click', (e) => {
    const btn = e.target.closest('.verdict-tab');
    if (!btn) return;
    document.querySelectorAll('.verdict-tab').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    verdictFilter = btn.dataset.v;
    renderRows();
  });

  const setProgress = (done, total) => {
    const pct = total > 0 ? Math.round((done / total) * 100) : 0;
    $('#d-prog-text').textContent = `${done} / ${total}`;
    $('#d-prog-pct').textContent = pct + '%';
    $('#d-prog-fill').style.width = pct + '%';
  };
  setProgress(scan.DoneTasks, scan.TotalTasks);

  const bumpVerdict = (v) => {
    const tile = $(`[data-verdict-tile="${v}"]`);
    if (!tile) return;
    const numEl = $(`#d-num-${v}`);
    numEl.textContent = Number(numEl.textContent) + 1;
    tile.classList.remove('zero');
  };

  // 加载已有结果
  try {
    const resData = await API.get(`/scans/${id}/results`);
    (resData.results || []).forEach((r) => rows.push(r));
    renderRows();
  } catch (e) { /* 已结束扫描无结果时忽略 */ }

  // 任务流量：分页表格（仅已结束扫描有完整流量，运行中也可看已落库部分）
  const trafficEl = $('#d-traffic');
  const trafficInfo = $('#d-traffic-info');
  const fmtBytes = (n) => n >= 1024 ? (n / 1024).toFixed(1) + 'K' : n + 'B';

  const trafficRow = (t) => `
    <tr>
      <td class="mono">${t.Seq}</td>
      <td class="mono">${esc(t.Protocol || '?')}</td>
      <td>${t.Matched ? '<span style="color:var(--green)">✓</span>' : '<span style="color:var(--muted)">—</span>'}</td>
      <td class="mono">${t.Status || '-'}</td>
      <td class="mono ellipsis" style="max-width:220px" title="${esc(t.TemplateID)}">${esc(t.TemplateID)}</td>
      <td class="mono ellipsis" style="max-width:240px" title="${esc(t.TargetURL)}">${esc(t.TargetURL)}</td>
      <td class="mono">${fmtBytes((t.Request || '').length)}${t.ReqTruncated ? '*' : ''} / ${fmtBytes((t.Response || '').length)}${t.RespTruncated ? '*' : ''}</td>
      <td><button class="btn btn-sm" onclick="showTrafficModal(${id}, ${t.POCID}, ${t.TargetID})">查看</button></td>
    </tr>`;

  const loadTraffic = async () => {
    try {
      const params = new URLSearchParams({ limit: String(trafficPage.limit), offset: String(trafficPage.offset) });
      const d = await API.get(`/scans/${id}/traffic?` + params.toString());
      trafficPage.total = d.total || 0;
      const list = d.traffic || [];
      trafficEl.innerHTML = list.map(trafficRow).join('')
        || `<tr><td colspan="8" class="empty">暂无流量记录（旧扫描无流量，或配置 traffic_save=false）</td></tr>`;
      const from = trafficPage.total ? trafficPage.offset + 1 : 0;
      const to = trafficPage.offset + list.length;
      trafficInfo.textContent = trafficPage.total > 0
        ? `第 ${from}-${to} 条 / 共 ${trafficPage.total} 条（* 表示已截断，上限见配置 traffic_max_bytes；按特征筛选请用「结果明细」页签）`
        : '';
      $('#d-traffic-prev').disabled = trafficPage.offset <= 0;
      $('#d-traffic-next').disabled = trafficPage.offset + trafficPage.limit >= trafficPage.total;
    } catch (e) { trafficInfo.textContent = '流量加载失败：' + e.message; }
  };
  $('#d-traffic-prev').onclick = () => {
    trafficPage.offset = Math.max(0, trafficPage.offset - trafficPage.limit);
    loadTraffic();
  };
  $('#d-traffic-next').onclick = () => {
    if (trafficPage.offset + trafficPage.limit < trafficPage.total) {
      trafficPage.offset += trafficPage.limit;
      loadTraffic();
    }
  };
  $('#d-traffic-size').addEventListener('change', (e) => {
    trafficPage.limit = Number(e.target.value) || 50;
    trafficPage.offset = 0;
    loadTraffic();
  });
  loadTraffic();

  // 镜像连接流水：分页表格（socks5 镜像代理逐连接记录，运行中亦可看已落库部分）
  const dumpEl = $('#d-dump');
  const dumpInfo = $('#d-dump-info');
  const fmtMs = (n) => n >= 1000 ? (n / 1000).toFixed(1) + 's' : n + 'ms';

  const dumpRow = (d) => `
    <tr>
      <td class="mono">${d.Seq}</td>
      <td class="mono ellipsis" style="max-width:260px" title="${esc(d.Addr)}">${esc(d.Addr)}</td>
      <td class="mono">${fmtMs(d.DurationMs || 0)}</td>
      <td class="mono">${fmtBytes(d.ClientLen || 0)}${d.ClientTrunc ? '*' : ''}</td>
      <td class="mono">${fmtBytes(d.ServerLen || 0)}${d.ServerTrunc ? '*' : ''}</td>
      <td><button class="btn btn-sm" title="查看该连接完整双向字节流" onclick="showDumpModal(${id}, ${d.Seq})">查看</button></td>
    </tr>`;

  const loadDump = async () => {
    try {
      const params = new URLSearchParams({ limit: String(dumpPage.limit), offset: String(dumpPage.offset) });
      const d = await API.get(`/scans/${id}/dump?` + params.toString());
      dumpPage.total = d.total || 0;
      const list = d.dump || [];
      dumpEl.innerHTML = list.map(dumpRow).join('')
        || `<tr><td colspan="6" class="empty">暂无镜像连接记录（traffic_save=false，或旧版本扫描未启用镜像代理）</td></tr>`;
      const from = dumpPage.total ? dumpPage.offset + 1 : 0;
      const to = dumpPage.offset + list.length;
      dumpInfo.textContent = dumpPage.total > 0
        ? `第 ${from}-${to} 条 / 共 ${dumpPage.total} 条连接（* 表示已截断，上限见配置 traffic_max_bytes；单条连接可能含多个复用请求）`
        : '';
      $('#d-dump-prev').disabled = dumpPage.offset <= 0;
      $('#d-dump-next').disabled = dumpPage.offset + dumpPage.limit >= dumpPage.total;
    } catch (e) { dumpInfo.textContent = '镜像连接加载失败：' + e.message; }
  };
  $('#d-dump-prev').onclick = () => {
    dumpPage.offset = Math.max(0, dumpPage.offset - dumpPage.limit);
    loadDump();
  };
  $('#d-dump-next').onclick = () => {
    if (dumpPage.offset + dumpPage.limit < dumpPage.total) {
      dumpPage.offset += dumpPage.limit;
      loadDump();
    }
  };
  $('#d-dump-size').addEventListener('change', (e) => {
    dumpPage.limit = Number(e.target.value) || 50;
    dumpPage.offset = 0;
    loadDump();
  });
  loadDump();

  // 运行中：订阅 SSE 实时更新
  if (scan.Status === 'running') {
    const es = new EventSource(`/api/v1/scans/${id}/events`);
    let done = scan.DoneTasks, total = scan.TotalTasks;

    es.addEventListener('progress', (ev) => {
      const d = JSON.parse(ev.data);
      done = d.done ?? done; total = d.total ?? total;
      setProgress(done, total);
    });
    es.addEventListener('result', (ev) => {
      const d = JSON.parse(ev.data);
      if (d.result) {
        // SSE 载荷为小写字段名，归一化为 store 结果字段名（与 /results 接口一致）
        const p = d.result;
        rows.push({
          TargetID: p.target_id, POCID: p.poc_id, TemplateID: p.template_id,
          Severity: p.severity, Verdict: p.verdict, TargetURL: p.target_url,
          ResponseStatus: p.response_status, ErrorText: p.error_text,
        });
        bumpVerdict(p.verdict);
        renderRows();
      }
    });
    es.addEventListener('done', (ev) => {
      const d = JSON.parse(ev.data);
      $('#d-prog-fill').classList.add('done');
      setProgress(d.done ?? done, d.total ?? total);
      $('#d-live-badge').textContent = '■ 已结束';
      $('#d-live-badge').style.color = 'var(--muted)';
      $('#d-status-extra').textContent = d.status ? `状态：${d.status}` : '';
      const tabBtn = $('#d-page-tabs .page-tab[data-tab="results"]');
      if (tabBtn) tabBtn.innerHTML = '📋 结果明细';
      // 终态刷新一次权威数据
      setTimeout(async () => {
        try { const s = await API.get(`/scans/${id}`); Object.assign(scan, s); } catch (e) {}
      }, 500);
      es.close();
    });
    es.addEventListener('error', () => { /* 连接断开由心跳轮询兜底 */ });
    currentCleanup = () => es.close();
  } else {
    $('#d-live-badge').textContent = '■ 已结束';
    $('#d-live-badge').style.color = 'var(--muted)';
    $('#d-prog-fill').classList.add('done');
    $('#d-prog-fill').style.width = '100%';
  }

  $('#d-refresh').onclick = () => router();
  $('#d-cancel')?.addEventListener('click', async () => {
    if (!confirmBox(`确认取消扫描 #${id}？`)) return;
    try { await API.post(`/scans/${id}/cancel`); toast('取消请求已发送', 'success'); }
    catch (e) { toast(e.message, 'error'); }
  });
  $('#d-delete')?.addEventListener('click', async () => {
    await deleteScan(Number(id), scan.Name || '');
  });
}

/* 流量详情弹窗：展示单个任务（POC×目标）全部事件的完整请求/响应包。
   同一任务多事件（多请求模板/攻击链）按 SEQ 顺序堆叠展示。 */
async function showTrafficModal(scanID, pocID, targetID) {
  $('#modal-root').innerHTML = `
    <div class="modal-overlay" onclick="if(event.target===this)closeModal()">
      <div class="modal traffic-modal">
        <div class="modal-header">
          <h3>📦 任务流量</h3>
          <button class="modal-close" onclick="closeModal()">×</button>
        </div>
        <div class="modal-body"><div class="loading"><div class="spinner"></div>加载中...</div></div>
      </div>
    </div>`;
  try {
    const d = await API.get(`/scans/${scanID}/traffic?poc_id=${pocID}&target_id=${targetID}&limit=100`);
    const list = d.traffic || [];
    if (!list.length) {
      $('#modal-root .modal-body').innerHTML = '<div class="empty"><div class="empty-icon">📦</div><div>该任务无流量记录</div></div>';
      return;
    }
    const head = list[0];
    const eventBlock = (t) => `
      <div class="traffic-event">
        <div class="traffic-event-head">
          <span class="mono">SEQ ${t.Seq}</span>
          <span class="badge">${esc(t.Protocol || 'unknown')}</span>
          ${t.Matched ? '<span class="badge badge-exec-ok">匹配</span>' : '<span class="badge badge-exec-no">未匹配</span>'}
          ${t.Status ? `<span class="badge">HTTP ${t.Status}</span>` : ''}
          <span style="color:var(--muted);font-size:11px">${fmtTime(t.CreatedAt)}</span>
        </div>
        <div class="traffic-label">REQUEST ${t.ReqTruncated ? '<span class="traffic-trunc">（已截断）</span>' : ''}</div>
        <pre class="traffic-pre">${t.Request ? esc(t.Request) : '（无请求包）'}</pre>
        <div class="traffic-label">RESPONSE ${t.RespTruncated ? '<span class="traffic-trunc">（已截断）</span>' : ''}</div>
        <pre class="traffic-pre">${t.Response ? esc(t.Response) : '（无响应包）'}</pre>
      </div>`;
    $('#modal-root .modal-body').innerHTML = `
      <dl class="kv-list" style="margin-bottom:14px">
        <dt>模板</dt><dd class="mono">${esc(head.TemplateID || `#${pocID}`)}</dd>
        <dt>目标</dt><dd class="mono">${esc(head.TargetURL || `#${targetID}`)}</dd>
        <dt>事件数</dt><dd class="mono">${list.length}${(d.total || 0) > list.length ? `（仅显示前 ${list.length} 条）` : ''}</dd>
      </dl>
      ${list.map(eventBlock).join('')}`;
  } catch (e) {
    $('#modal-root .modal-body').innerHTML = `<div class="empty"><div class="empty-icon">⚠</div><div>${esc(e.message)}</div></div>`;
  }
}

/* 镜像连接详情弹窗：展示单条连接的双向完整字节流。
   seq 连续且按序分页（offset=seq-1&limit=1 精确定位），同一连接内
   keep-alive 复用的多个请求按原始顺序堆叠在客户端数据中。 */
async function showDumpModal(scanID, seq) {
  $('#modal-root').innerHTML = `
    <div class="modal-overlay" onclick="if(event.target===this)closeModal()">
      <div class="modal traffic-modal">
        <div class="modal-header">
          <h3>🔗 镜像连接 #${seq}</h3>
          <button class="modal-close" onclick="closeModal()">×</button>
        </div>
        <div class="modal-body"><div class="loading"><div class="spinner"></div>加载中...</div></div>
      </div>
    </div>`;
  try {
    const d = await API.get(`/scans/${scanID}/dump?limit=1&offset=${seq - 1}`);
    const c = (d.dump || [])[0];
    if (!c || c.Seq !== seq) {
      $('#modal-root .modal-body').innerHTML = '<div class="empty"><div class="empty-icon">🔗</div><div>未找到该连接记录</div></div>';
      return;
    }
    const fmtMs = (n) => n >= 1000 ? (n / 1000).toFixed(1) + 's' : n + 'ms';
    const nReq = (c.ClientData.match(/(GET |POST |PUT |DELETE |HEAD |OPTIONS |PATCH )\S+ HTTP\//g) || []).length;
    $('#modal-root .modal-body').innerHTML = `
      <dl class="kv-list" style="margin-bottom:14px">
        <dt>连接目标</dt><dd class="mono">${esc(c.Addr)}</dd>
        <dt>开始时间</dt><dd class="mono">${fmtTime(c.StartedAt)}</dd>
        <dt>持续耗时</dt><dd class="mono">${fmtMs(c.DurationMs || 0)}</dd>
        <dt>流量统计</dt><dd class="mono">客户端→服务端 ${c.ClientLen || 0}B${c.ClientTrunc ? '（已截断）' : ''} / 服务端→客户端 ${c.ServerLen || 0}B${c.ServerTrunc ? '（已截断）' : ''}${nReq ? ` / 检出 ${nReq} 个 HTTP 请求（keep-alive 复用）` : ''}</dd>
      </dl>
      <div class="traffic-event">
        <div class="traffic-event-head"><span class="badge">客户端 → 服务端</span>
          <span style="color:var(--muted);font-size:11px">攻击侧发出的全部字节（含中间请求）</span></div>
        <pre class="traffic-pre">${c.ClientData ? esc(c.ClientData) : '（无数据）'}</pre>
      </div>
      <div class="traffic-event">
        <div class="traffic-event-head"><span class="badge">服务端 → 客户端</span>
          <span style="color:var(--muted);font-size:11px">目标返回的全部字节</span></div>
        <pre class="traffic-pre">${c.ServerData ? esc(c.ServerData) : '（无数据）'}</pre>
      </div>`;
  } catch (e) {
    $('#modal-root .modal-body').innerHTML = `<div class="empty"><div class="empty-icon">⚠</div><div>${esc(e.message)}</div></div>`;
  }
}

/* ============ 视图：POC 源同步 ============ */
async function renderSync(main) {
  const settings = await apiGuard(() => API.get('/settings'));
  const cfgProxy = settings.proxy || '';

  main.innerHTML = `
    <div class="page-header">
      <div><div class="page-title">POC 源同步</div>
      <div class="page-desc">从 GitHub 克隆/更新 POC 模板仓库（访问 GitHub 超时时建议走代理），同步后需重建索引</div></div>
    </div>
    <div class="card">
      <div class="card-title">同步选项</div>
      <div class="form-grid">
        <div class="form-item"><label>代理模式</label>
          <select id="y-proxy-mode">
            <option value="config" selected>使用全局配置${cfgProxy ? `（${esc(cfgProxy)}）` : '（当前为直连）'}</option>
            <option value="direct">本次直连（不走代理）</option>
            <option value="custom">自定义代理…</option>
          </select>
          <span class="hint" id="y-proxy-hint">${cfgProxy ? '配置代理来自 config.yaml 的 network.proxy' : '当前配置未设置代理'}</span></div>
        <div class="form-item" id="y-proxy-custom-item" style="display:none"><label>代理地址</label>
          <input type="text" id="y-proxy-custom" placeholder="http://127.0.0.1:7897">
          <span class="hint">支持 http/socks5，仅对本次同步的 git 流量生效</span></div>
        <div class="form-item"><label>并发数</label>
          <input type="number" id="y-workers" value="4" min="1" max="16"></div>
        <div class="form-item"><label>导入 repo.csv（可选）</label>
          <input type="text" id="y-csv" placeholder="服务器上 repo.csv 的绝对路径（首次迁移旧清单）"></div>
      </div>
      <div style="margin-top:14px;display:flex;gap:10px">
        <button class="btn btn-primary" id="y-sync">🔄 开始同步</button>
        <button class="btn btn-success" id="y-index">📦 重建索引</button>
      </div>
      <div id="y-progress" class="progress-wrap" style="display:none">
        <div class="progress-info">
          <span id="y-prog-text">0 / 0</span>
          <span><span id="y-prog-counts" style="margin-right:10px"></span><span id="y-prog-pct">0%</span></span>
        </div>
        <div class="progress-bar"><div class="progress-fill" id="y-prog-fill"></div></div>
      </div>
      <div id="y-status" style="margin-top:12px;color:var(--muted);font-size:13px"></div>
    </div>
    <div class="card" id="y-results-card" style="display:none">
      <div class="card-title">实时结果 <span id="y-live-badge" style="font-size:11px;color:var(--green)">● LIVE</span></div>
      <div id="y-live-list" class="live-results" style="max-height:360px;overflow-y:auto"></div>
    </div>`;

  // 代理模式切换：自定义时显示输入框
  $('#y-proxy-mode').onchange = (e) => {
    $('#y-proxy-custom-item').style.display = e.target.value === 'custom' ? '' : 'none';
  };

  // 恢复进行中/刚结束的同步状态（页面刷新场景）
  try {
    const st = await API.get('/sync/status');
    if (st.total > 0 && (st.running || st.finished)) {
      $('#y-progress').style.display = '';
      $('#y-results-card').style.display = '';
      let ok = 0, bad = 0;
      const icons = { cloned: '＋', updated: '↻', skipped: '－', failed: '✗' };
      (st.results || []).forEach((r) => {
        r.status === 'failed' ? bad++ : ok++;
        const row = document.createElement('div');
        row.className = 'sync-item';
        row.innerHTML = `
          <span class="sync-status sync-icon-${r.status}">${icons[r.status] || '?'} ${r.status}</span>
          <span class="sync-url" title="${esc(r.source?.url || '')}">${esc(r.source?.url || '')}</span>
          <span class="mono" style="color:var(--muted)">${r.duration_ms}ms</span>
          ${r.err ? `<span class="sync-err" title="${esc(r.err)}">${esc(r.err)}</span>` : ''}`;
        $('#y-live-list').appendChild(row);
      });
      const pct = st.total > 0 ? Math.round((st.done / st.total) * 100) : 0;
      $('#y-prog-text').textContent = `${st.done} / ${st.total}`;
      $('#y-prog-pct').textContent = pct + '%';
      $('#y-prog-fill').style.width = pct + '%';
      $('#y-prog-counts').textContent = `成功 ${ok} · 失败 ${bad}`;
      if (st.finished) {
        $('#y-prog-fill').classList.add('done');
        $('#y-live-badge').textContent = '■ 已结束';
        $('#y-live-badge').style.color = 'var(--muted)';
        $('#y-status').textContent = `上次同步：成功 ${ok} / 失败 ${bad}`;
      } else {
        $('#y-sync').disabled = true;
        $('#y-status').textContent = `同步进行中（刷新页面可恢复进度显示）...`;
      }
    }
  } catch (e) { /* 无状态时忽略 */ }

  // resolveProxy 计算本次同步的 proxy 覆盖值（undefined = 沿用配置）
  const resolveProxy = () => {
    const mode = $('#y-proxy-mode').value;
    if (mode === 'config') return undefined;
    if (mode === 'direct') return '';
    const p = $('#y-proxy-custom').value.trim();
    if (!p) { toast('请输入代理地址', 'error'); return null; }
    return p;
  };

  $('#y-sync').onclick = async (e) => {
    const proxy = resolveProxy();
    if (proxy === null) return;
    const btn = e.target;
    btn.disabled = true;
    const proxyLabel = proxy === undefined ? (cfgProxy || '直连') : (proxy || '直连');
    $('#y-status').textContent = `启动同步（git 流量走 ${proxyLabel}）...`;

    // 进度区就绪
    const prog = $('#y-progress');
    prog.style.display = '';
    $('#y-prog-fill').style.width = '0%';
    $('#y-prog-fill').classList.remove('done');
    $('#y-prog-text').textContent = '0 / 0';
    $('#y-prog-pct').textContent = '0%';
    const counts = { ok: 0, failed: 0 };
    const cntEl = $('#y-prog-counts');
    cntEl.textContent = '';
    const listEl = $('#y-live-list');
    listEl.innerHTML = '';
    $('#y-results-card').style.display = '';

    try {
      await API.post('/sync', {
        import_csv: $('#y-csv').value.trim() || undefined,
        workers: Number($('#y-workers').value) || 4,
        proxy,
      });
    } catch (err) {
      $('#y-status').textContent = '同步启动失败：' + err.message;
      toast(err.message, 'error');
      btn.disabled = false;
      return;
    }

    // SSE 实时订阅进度
    const icons = { cloned: '＋', updated: '↻', skipped: '－', failed: '✗' };
    const appendResult = (r) => {
      const row = document.createElement('div');
      row.className = 'sync-item';
      row.innerHTML = `
        <span class="sync-status sync-icon-${r.status}">${icons[r.status] || '?'} ${r.status}</span>
        <span class="sync-url" title="${esc(r.source?.url || '')}">${esc(r.source?.url || '')}</span>
        <span class="mono" style="color:var(--muted)">${r.duration_ms}ms</span>
        ${r.err ? `<span class="sync-err" title="${esc(r.err)}">${esc(r.err)}</span>` : ''}`;
      listEl.appendChild(row);
      // 自动滚动到最新
      listEl.scrollTop = listEl.scrollHeight;
    };
    const setProgress = (done, total) => {
      const pct = total > 0 ? Math.round((done / total) * 100) : 0;
      $('#y-prog-text').textContent = `${done} / ${total}`;
      $('#y-prog-pct').textContent = pct + '%';
      $('#y-prog-fill').style.width = pct + '%';
      cntEl.textContent = `成功 ${counts.ok} · 失败 ${counts.failed}`;
    };

    const es = new EventSource('/api/v1/sync/events');
    es.addEventListener('progress', (ev) => {
      const d = JSON.parse(ev.data);
      setProgress(d.done, d.total);
    });
    es.addEventListener('result', (ev) => {
      const d = JSON.parse(ev.data);
      if (d.result) {
        if (d.result.status === 'failed') counts.failed++;
        else counts.ok++;
        appendResult(d.result);
      }
    });
    es.addEventListener('done', (ev) => {
      const d = JSON.parse(ev.data);
      setProgress(d.done, d.total);
      $('#y-prog-fill').classList.add('done');
      es.close();
      btn.disabled = false;
      if (d.err_text) {
        $('#y-status').textContent = `同步失败：${d.err_text}（代理：${proxyLabel}）`;
        toast(d.err_text, 'error');
      } else {
        $('#y-status').textContent = `同步完成（代理：${proxyLabel}）：成功 ${counts.ok} / 失败 ${counts.failed}`;
        toast('POC 源同步完成', 'success');
      }
    });
    es.onerror = () => {
      // 连接断开：轮询终态兜底
      es.close();
      (async () => {
        for (let i = 0; i < 60; i++) {
          await new Promise((r) => setTimeout(r, 2000));
          try {
            const st = await API.get('/sync/status');
            if (st.finished) {
              setProgress(st.done, st.total);
              $('#y-prog-fill').classList.add('done');
              btn.disabled = false;
              $('#y-status').textContent = `同步结束（代理：${proxyLabel}）：成功 ${counts.ok} / 失败 ${counts.failed}`;
              return;
            }
          } catch (e) { /* 继续轮询 */ }
        }
        btn.disabled = false;
      })();
    };
  };

  $('#y-index').onclick = async (e) => {
    const btn = e.target;
    btn.disabled = true;
    $('#y-status').textContent = '重建索引中（解析全部模板 YAML）...';
    // 索引进度条（复用同步进度区）
    $('#y-progress').style.display = '';
    $('#y-prog-fill').classList.remove('done');
    $('#y-prog-fill').style.width = '0%';
    $('#y-prog-text').textContent = '0 / 0';
    $('#y-prog-pct').textContent = '0%';
    $('#y-prog-counts').textContent = '阶段一：收集模板文件...';
    try {
      await API.post('/pocs/index');
    } catch (err) {
      $('#y-status').textContent = '索引启动失败：' + err.message;
      toast(err.message, 'error');
      btn.disabled = false;
      return;
    }

    const es = new EventSource('/api/v1/pocs/index/events');
    es.addEventListener('progress', (ev) => {
      const d = JSON.parse(ev.data);
      const pct = d.total > 0 ? Math.round((d.done / d.total) * 100) : 0;
      $('#y-prog-text').textContent = `${d.done} / ${d.total}`;
      $('#y-prog-pct').textContent = pct + '%';
      $('#y-prog-fill').style.width = pct + '%';
      $('#y-prog-counts').textContent = d.current_repo ? `当前: ${d.current_repo}` : '';
    });
    es.addEventListener('done', (ev) => {
      const d = JSON.parse(ev.data);
      es.close();
      btn.disabled = false;
      $('#y-prog-fill').classList.add('done');
      if (d.err_text) {
        $('#y-status').textContent = '索引失败：' + d.err_text;
        toast(d.err_text, 'error');
      } else {
        const st = d.stats || {};
        $('#y-prog-counts').textContent = '';
        $('#y-status').textContent = `索引完成：仓库 ${st.repos ?? '-'} · 文件 ${st.files ?? '-'} · 入库 ${st.indexed ?? '-'} · 去重 ${st.duplicates ?? '-'} · 无效 ${st.invalid ?? '-'} · 引擎拒载 ${st.engine_rejected ?? '-'}`;
        toast('索引重建完成', 'success');
      }
    });
    es.onerror = () => {
      // 连接断开：轮询终态兜底
      es.close();
      (async () => {
        for (let i = 0; i < 60; i++) {
          await new Promise((r) => setTimeout(r, 2000));
          try {
            const st = await API.get('/pocs/index/status');
            if (st.finished) {
              btn.disabled = false;
              $('#y-prog-fill').classList.add('done');
              const s = st.stats || {};
              $('#y-status').textContent = st.err_text
                ? '索引失败：' + st.err_text
                : `索引完成：仓库 ${s.repos ?? '-'} · 入库 ${s.indexed ?? '-'}`;
              return;
            }
          } catch (e) { /* 继续轮询 */ }
        }
        btn.disabled = false;
      })();
    };
  };
}

/* ============ 视图：登录 ============ */
// renderLogin 登录页（全屏居中，隐藏侧边栏由 body.auth-page 控制）。
async function renderLogin(main) {
  main.innerHTML = `
    <div class="auth-wrap">
      <div class="auth-card">
        <div class="auth-logo">🛡</div>
        <h1 class="auth-title">GoBAS</h1>
        <p class="auth-sub">入侵与攻击模拟平台</p>
        <form id="login-form">
          <label class="auth-label" for="login-user">用户名</label>
          <input class="input" id="login-user" type="text" autocomplete="username" placeholder="admin" required>
          <label class="auth-label" for="login-pwd">密码</label>
          <input class="input" id="login-pwd" type="password" autocomplete="current-password" placeholder="请输入密码" required>
          <div class="auth-err" id="login-err"></div>
          <button class="btn btn-primary btn-block" type="submit">登 录</button>
        </form>
        <p class="auth-hint">首次登录：初始密码见启动服务的控制台，登录后将强制修改<br>忘记密码可执行 gobas auth reset-password 重置</p>
      </div>
    </div>`;
  $('#login-form').onsubmit = async (e) => {
    e.preventDefault();
    const box = $('#login-err');
    box.textContent = '';
    const submit = $('#login-form').querySelector('button[type=submit]');
    submit.disabled = true;
    try {
      const res = await API.post('/auth/login', {
        username: $('#login-user').value.trim(),
        password: $('#login-pwd').value,
      });
      authState = { enabled: true, authenticated: true, username: res.username, must_change_password: !!res.must_change_password };
      toast('登录成功', 'success');
      location.hash = res.must_change_password ? '#/change-password' : '#/dashboard';
    } catch (err) {
      box.textContent = err.message;
      submit.disabled = false;
    }
  };
}

/* ============ 视图：修改/强制改密 ============ */
async function renderChangePassword(main) {
  const forced = authState.must_change_password;
  main.innerHTML = `
    <div class="auth-wrap">
      <div class="auth-card">
        <div class="auth-logo">🔑</div>
        <h1 class="auth-title">${forced ? '首次登录请设置新密码' : '修改密码'}</h1>
        <p class="auth-sub">当前用户：${esc(authState.username || 'admin')}</p>
        <form id="pwd-form">
          <label class="auth-label" for="pwd-old">当前密码</label>
          <input class="input" id="pwd-old" type="password" autocomplete="current-password" required>
          <label class="auth-label" for="pwd-new">新密码（至少 8 位）</label>
          <input class="input" id="pwd-new" type="password" autocomplete="new-password" required>
          <label class="auth-label" for="pwd-confirm">确认新密码</label>
          <input class="input" id="pwd-confirm" type="password" autocomplete="new-password" required>
          <div class="auth-err" id="pwd-err"></div>
          <button class="btn btn-primary btn-block" type="submit">${forced ? '设置新密码并进入' : '确认修改'}</button>
        </form>
        ${forced ? '<p class="auth-hint">修改成功后将跳转仪表盘</p>'
                 : '<p class="auth-hint"><a href="#/dashboard">返回仪表盘</a></p>'}
      </div>
    </div>`;
  $('#pwd-form').onsubmit = async (e) => {
    e.preventDefault();
    const box = $('#pwd-err');
    box.textContent = '';
    const n1 = $('#pwd-new').value, n2 = $('#pwd-confirm').value;
    if (n1 !== n2) { box.textContent = '两次输入的新密码不一致'; return; }
    const submit = $('#pwd-form').querySelector('button[type=submit]');
    submit.disabled = true;
    try {
      await API.post('/auth/change-password', {
        old_password: $('#pwd-old').value,
        new_password: n1,
      });
      authState.must_change_password = false;
      toast('密码修改成功', 'success');
      location.hash = '#/dashboard';
    } catch (err) {
      box.textContent = err.message;
      submit.disabled = false;
    }
  };
}

/* ============ 启动 ============ */
(async function init() {
  try { await API.get('/healthz'); }
  catch (e) { $('#engine-status').classList.add('offline'); $('#engine-status').innerHTML = '<span class="dot"></span>服务异常'; }
  // 右上角头像下拉：修改密码 / 退出登录
  const avatarBtn = $('#avatar-btn');
  const dropdown = $('#user-dropdown');
  if (avatarBtn && dropdown) {
    avatarBtn.onclick = (e) => {
      e.stopPropagation();
      dropdown.classList.toggle('hidden');
    };
    // 点击下拉外部任意处收起
    document.addEventListener('click', (e) => {
      if (!dropdown.classList.contains('hidden') && !dropdown.contains(e.target)) {
        dropdown.classList.add('hidden');
      }
    });
  }
  const udPwd = $('#ud-change-pwd');
  if (udPwd) udPwd.onclick = () => { if (dropdown) dropdown.classList.add('hidden'); location.hash = '#/change-password'; };
  const udOut = $('#ud-logout');
  if (udOut) udOut.onclick = async () => {
    if (dropdown) dropdown.classList.add('hidden');
    try { await API.post('/auth/logout'); } catch (e) { /* 即使失败也回登录页 */ }
    authState = { enabled: true, authenticated: false, username: '', must_change_password: false };
    location.hash = '#/login';
  };
  router();
})();
