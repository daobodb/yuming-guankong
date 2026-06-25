const DEFAULT_CONFIG = {
  SITENAME: '域名到期监控',
  DAYS: 30,
  ICON: '', 
  BGIMG: 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?q=80&w=1920',
  BLOG_URL: '',
  BLOG_NAME: ''
};

function maskData(str, type) {
  if (!str) return '';
  if (type === 'domain') {
    const parts = str.split('.');
    if (parts.length <= 1) return '***';
    const suffix = parts.slice(-1)[0];
    if(parts.length === 2) return `*****.${suffix}`;
    return `*****.*****.${suffix}`;
  }
  if (type === 'account') {
    if (str.length <= 4) return '****';
    return str.substring(0, 2) + '***********' + str.substring(str.length - 2);
  }
  return str;
}

function formatDate(dateStr) {
  if (!dateStr) return '';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    return d.toISOString().split('T')[0];
  } catch (e) { return dateStr; }
}

function parseCookies(request) {
  const list = {};
  const rc = request.headers.get('Cookie');
  if (rc) {
    rc.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
  }
  return list;
}

function checkAuth(request, env) {
  const cookies = parseCookies(request);
  return cookies['auth'] === (env.PASSWORD || '123123');
}

async function fetchWhois(domain) {
  try {
    const res = await fetch(`https://api.ip.sb/whois/${domain}`, {
      headers: { 'User-Agent': 'Mozilla/5.0' },
      cf: { cacheTtl: 3600 }
    });
    if (res.ok) {
      const data = await res.json();
      if (data && (data.expire_time || data.expires_at || data.expiration_date)) {
        return {
          registrar: data.registrar || '',
          registration_date: formatDate(data.create_time || data.created_at || data.creation_date),
          expiration_date: formatDate(data.expire_time || data.expires_at || data.expiration_date)
        };
      }
    }
  } catch (e) {}

  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, { cf: { cacheTtl: 3600 } });
    if (res.ok) {
      const data = await res.json();
      let expiration_date = '', registration_date = '', registrar = '';
      if (data.events) {
        const expEvent = data.events.find(e => e.eventAction === 'expiration');
        if (expEvent) expiration_date = formatDate(expEvent.eventDate);
        const regEvent = data.events.find(e => e.eventAction === 'registration');
        if (regEvent) registration_date = formatDate(regEvent.eventDate);
      }
      if (data.entities && data.entities.length > 0) {
        const vcard = data.entities[0].vcardArray;
        if (vcard && vcard[1]) {
          const fn = vcard[1].find(item => item[0] === 'fn');
          if (fn) registrar = fn[3];
        }
      }
      if (expiration_date) return { registrar, registration_date, expiration_date };
    }
  } catch (e) {}
  return null;
}

async function handleScheduled(env) {
  if (!env.DOMAIN_KV) return;
  const list = await env.DOMAIN_KV.list({ prefix: 'domain:' });
  const alertDays = parseInt(env.DAYS || DEFAULT_CONFIG.DAYS);
  const tgId = env.TGID;
  const tgToken = env.TGTOKEN;
  if (!tgId || !tgToken) return;

  let msg = '⚠️ *域名到期监控提醒* ⚠️\n\n';
  let hasExpired = false;

  for (const key of list.keys) {
    const rawData = await env.DOMAIN_KV.get(key.name);
    if (!rawData) continue;
    const domainData = JSON.parse(rawData);
    if (!domainData.expiration_date) continue;

    const exp = new Date(domainData.expiration_date);
    const diffDays = Math.ceil((exp - new Date()) / (1000 * 60 * 60 * 24));

    if (diffDays <= alertDays) {
      hasExpired = true;
      msg += `🌐 *域名*: \`${domainData.domain}\`\n⏳ *剩余*: ${diffDays} 天\n📅 *到期*: ${domainData.expiration_date}\n🏢 *服务商*: ${domainData.registrar || '未知'}\n\n`;
    }
  }

  if (hasExpired) {
    await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: tgId, text: msg, parse_mode: 'Markdown' })
    });
  }
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(handleScheduled(env));
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const isAuthed = checkAuth(request, env);

    if (url.pathname === '/login' && request.method === 'POST') {
      const data = await request.json();
      const expectedPassword = env.PASSWORD || '123123';
      if (data.password === expectedPassword) {
        return new Response(JSON.stringify({ success: true }), {
          headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': `auth=${expectedPassword}; Path=/; Max-Age=604800; Secure; SameSite=Strict`
          }
        });
      }
      return new Response(JSON.stringify({ success: false, msg: '密码不匹配' }), { status: 401 });
    }

    if (url.pathname === '/logout') {
      return new Response('Redirecting...', {
        status: 302,
        headers: { 'Location': '/', 'Set-Cookie': 'auth=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; SameSite=Strict' }
      });
    }

    if (url.pathname === '/api/domains') {
      if (!isAuthed) return new Response('Unauthorized', { status: 401 });
      
      if (request.method === 'GET') {
        const list = await env.DOMAIN_KV.list({ prefix: 'domain:' });
        const domains = [];
        for (const key of list.keys) {
          const val = await env.DOMAIN_KV.get(key.name);
          if (val) domains.push(JSON.parse(val));
        }
        return new Response(JSON.stringify(domains), { headers: { 'Content-Type': 'application/json' } });
      }

      if (request.method === 'POST' || request.method === 'PUT') {
        const data = await request.json();
        if (Array.isArray(data)) {
          for (const item of data) {
            if (item.domain) await env.DOMAIN_KV.put(`domain:${item.domain}`, JSON.stringify(item));
          }
        } else {
          if (!data.domain) return new Response('Missing domain', { status: 400 });
          await env.DOMAIN_KV.put(`domain:${data.domain}`, JSON.stringify(data));
        }
        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
      }
    }

    if (url.pathname.startsWith('/api/domains/') && request.method === 'DELETE') {
      if (!isAuthed) return new Response('Unauthorized', { status: 401 });
      const domainName = url.pathname.replace('/api/domains/', '');
      await env.DOMAIN_KV.delete(`domain:${domainName}`);
      return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (url.pathname.startsWith('/api/whois/')) {
      const domainName = url.pathname.replace('/api/whois/', '');
      const whoisData = await fetchWhois(domainName);
      if (whoisData) return new Response(JSON.stringify(whoisData), { headers: { 'Content-Type': 'application/json' } });
      return new Response(JSON.stringify({ error: 'Failed' }), { status: 500 });
    }

    if (url.pathname === '/cron') {
      await handleScheduled(env);
      return new Response('Manual execution finished.');
    }

    const list = await env.DOMAIN_KV.list({ prefix: 'domain:' });
    const rawDomains = [];
    for (const key of list.keys) {
      const val = await env.DOMAIN_KV.get(key.name);
      if (val) rawDomains.push(JSON.parse(val));
    }

    const processedDomains = rawDomains.map(d => {
      if (isAuthed) return d;
      return { ...d, domain: maskData(d.domain, 'domain'), account: maskData(d.account, 'account') };
    });

    const config = {
      SITENAME: env.SITENAME || DEFAULT_CONFIG.SITENAME,
      DAYS: parseInt(env.DAYS || DEFAULT_CONFIG.DAYS),
      ICON: env.ICON || DEFAULT_CONFIG.ICON,
      BGIMG: env.BGIMG || DEFAULT_CONFIG.BGIMG,
      BLOG_URL: env.BLOG_URL || DEFAULT_CONFIG.BLOG_URL,
      BLOG_NAME: env.BLOG_NAME || DEFAULT_CONFIG.BLOG_NAME,
      isAuthed: isAuthed
    };

    return new Response(renderOriginalStyleHTML(processedDomains, config, rawDomains), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }
};

// ---------------- 前端模版 ----------------
function renderOriginalStyleHTML(domains, config, rawDomains) {
  const modeBadge = config.isAuthed ? '管理视图' : '访客视图';
  const base64Payload = config.isAuthed ? globalThis.btoa(unescape(encodeURIComponent(JSON.stringify(rawDomains)))) : '';

  let totalCount = domains.length;
  let normalCount = 0;
  let warningCount = 0;
  let expiredCount = 0;

  domains.forEach(d => {
    if (!d.expiration_date) {
      normalCount++;
      return;
    }
    const remain = Math.ceil((new Date(d.expiration_date) - new Date()) / (1000*60*60*24));
    if (remain < 0) expiredCount++;
    else if (remain <= config.DAYS) warningCount++;
    else normalCount++;
  });

  const cardsHtml = domains.map((d, index) => {
    const expDate = d.expiration_date ? new Date(d.expiration_date) : null;
    const regDate = d.registration_date ? new Date(d.registration_date) : null;
    const now = new Date();
    
    const remainDays = expDate ? Math.ceil((expDate - now) / (1000*60*60*24)) : -1;
    
    let usedDays = '-';
    let percent = 100;
    let statusText = '正常';
    let statusClass = 'badge-normal';
    
    if (regDate && expDate) {
      const totalDuration = expDate - regDate;
      const elapsed = now - regDate;
      if (totalDuration > 0) {
        percent = Math.min(100, Math.max(0, (elapsed / totalDuration) * 100));
        usedDays = Math.max(0, Math.floor(elapsed / (1000*60*60*24))) + ' 天';
      }
    }

    if (remainDays < 0) {
      statusText = '已到期';
      statusClass = 'badge-expired';
    } else if (remainDays <= config.DAYS) {
      statusText = '待到期';
      statusClass = 'badge-warn';
    }

    const groupLabel = d.group || '未分组';
    const domainParts = d.domain.split('.');
    const isLevel2 = domainParts.length > 2 ? '二级域名' : '一级域名';

    return `
      <div class="glass-card js-domain-card" data-domain="${d.domain}" data-group="${groupLabel}" data-level="${isLevel2}" data-status="${statusText}">
        <div class="card-title-row">
          <div class="dom-text">${d.domain}</div>
          <div style="display:flex; align-items:center; gap:8px;">
            <span class="status-badge ${statusClass}">${statusText}</span>
            ${config.isAuthed ? `<input type="checkbox" class="dom-selector" value="${d.domain}">` : ''}
          </div>
        </div>

        <div class="fields-grid">
          <div class="field-node"><span class="emoji-icon">⏹️</span><label>注册商</label><span class="val-text">${d.registrar || '未知'}</span></div>
          <div class="field-node"><span class="emoji-icon">👤</span><label>注册账号</label><span class="val-text">${d.account || '无'}</span></div>
          <div class="field-node"><span class="emoji-icon">📅</span><label>注册时间</label><span class="val-text">${d.registration_date || '未知'}</span></div>
          <div class="field-node"><span class="emoji-icon">🎁</span><label>到期时间</label><span class="val-text">${d.expiration_date || '未知'}</span></div>
        </div>
        
        <div class="bar-container">
          <div class="bar-fill" style="width: ${percent}%;"></div>
        </div>
        <div class="bar-legend"><span>已使用 ${usedDays}</span> <span>剩余 ${remainDays >= 0 ? remainDays + ' 天' : '已过期'}</span></div>

        <div class="card-footer-flex">
          <span class="tag-pill">🏷️ ${groupLabel}</span>
          ${config.isAuthed ? `
          <div class="opt-group">
            <button class="action-link" onclick="editDomain('${d.domain}', '${d.account}', '${d.registrar}', '${d.registration_date}', '${d.expiration_date}', '${groupLabel}')">编辑</button>
            <button class="action-link" onclick="cloneDomain('${d.account}', '${d.registrar}', '${groupLabel}')">克隆</button>
            <button class="action-link danger-link" onclick="deleteSingle('${d.domain}')">删除</button>
          </div>` : ''}
        </div>
      </div>
    `;
  }).join('');

  return `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${config.SITENAME}</title>
    ${config.ICON ? `<link rel="icon" href="${config.ICON}">` : ''}
    <style>
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: url('${config.BGIMG}') no-repeat center center fixed;
        background-size: cover; min-height: 100vh; padding: 30px 15px; display: flex; justify-content: center;
      }
      .panel {
        width: 100%; max-width: 1200px;
        background: rgba(255, 255, 255, 0.45); backdrop-filter: blur(25px); -webkit-backdrop-filter: blur(25px);
        border: 1px solid rgba(255, 255, 255, 0.4); border-radius: 24px; padding: 30px; box-shadow: 0 20px 40px rgba(0,0,0,0.06);
      }
      header {
        display: flex; justify-content: space-between; align-items: center;
        border-bottom: 1px solid rgba(255,255,255,0.3); padding-bottom: 20px; margin-bottom: 25px; flex-wrap: wrap; gap: 15px;
      }
      .logo-area { display: flex; align-items: center; gap: 12px; }
      .site-avatar { width: 36px; height: 36px; border-radius: 50%; object-fit: cover; }
      .logo-area h1 { font-size: 1.5rem; color: #1e293b; font-weight: 700; }
      .badge { font-size: 0.8rem; padding: 4px 12px; background: rgba(255,255,255,0.6); border: 1px solid rgba(255,255,255,0.4); border-radius: 50px; color: #475569; font-weight: 600; }
      
      .actions-container { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
      button {
        padding: 9px 16px; border-radius: 10px; border: none; cursor: pointer; font-weight: 600; font-size: 0.88rem; transition: all 0.2s;
        display: inline-flex; align-items: center; gap: 4px; white-space: nowrap; word-break: keep-all; min-width: max-content;
      }
      button.btn-primary { background: #2563eb; color: white; box-shadow: 0 4px 12px rgba(37,99,235,0.2); }
      button.btn-primary:hover { background: #1d4ed8; transform: translateY(-1px); }
      button.btn-secondary { background: rgba(255,255,255,0.85); color: #1e293b; border: 1px solid rgba(0,0,0,0.06); }
      button.btn-secondary:hover { background: white; }

      .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
      .stat-card { background: rgba(255, 255, 255, 0.65); border: 1px solid rgba(255,255,255,0.5); border-radius: 14px; padding: 15px; text-align: center; border-left: 5px solid #2563eb; }
      .stat-card.sc-ok { border-left-color: #10b981; }
      .stat-card.sc-warn { border-left-color: #f59e0b; }
      .stat-card.sc-expired { border-left-color: #ef4444; }
      .stat-label { font-size: 0.88rem; color: #475569; font-weight: 600; margin-bottom: 5px; }
      .stat-value { font-size: 1.8rem; font-weight: 800; color: #0f172a; }

      .filter-bar { background: rgba(255, 255, 255, 0.5); border: 1px solid rgba(255,255,255,0.4); border-radius: 14px; padding: 12px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; }
      .tabs-row { display: flex; gap: 6px; flex-wrap: wrap; }
      .tab-btn { padding: 6px 14px; font-size: 0.85rem; background: rgba(255,255,255,0.8); color: #475569; border-radius: 8px; border: none; cursor: pointer; font-weight: 600; }
      .tab-btn.active, .tab-btn:hover { background: #2563eb; color: white; }
      .search-box { position: relative; width: 100%; max-width: 260px; }
      .search-box input { width: 100%; padding: 8px 12px 8px 32px; border-radius: 8px; border: 1px solid #cbd5e1; outline: none; font-size: 0.88rem; background: rgba(255,255,255,0.8); }

      .matrix-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(315px, 1fr)); gap: 20px; }
      .glass-card { background: rgba(255, 255, 255, 0.82); border: 1px solid rgba(255,255,255,0.6); border-radius: 18px; padding: 22px; display: flex; flex-direction: column; gap: 14px; }
      .card-title-row { display: flex; justify-content: space-between; align-items: center; }
      .dom-text { font-size: 1.15rem; font-weight: 700; color: #1e293b; word-break: break-all; }
      .status-badge { font-size: 0.75rem; padding: 2px 8px; border-radius: 6px; font-weight: 700; }
      .badge-normal { background: rgba(16, 185, 129, 0.15); color: #059669; }
      .badge-warn { background: rgba(245, 158, 11, 0.15); color: #d97706; }
      .badge-expired { background: rgba(239, 68, 68, 0.15); color: #dc2626; }

      .fields-grid { display: flex; flex-direction: column; gap: 8px; font-size: 0.88rem; color: #475569; }
      .field-node { display: flex; align-items: center; width: 100%; }
      .emoji-icon { width: 22px; display: inline-block; flex-shrink: 0; text-align: left; }
      .field-node label { width: 70px; color: #64748b; font-weight: 500; flex-shrink: 0; }
      .val-text { flex-grow: 1; text-align: right; font-weight: 600; color: #1e293b; word-break: break-all; padding-left: 10px; }

      .bar-container { height: 6px; background: rgba(0,0,0,0.05); border-radius: 100px; overflow: hidden; margin-top: 4px; }
      .bar-fill { height: 100%; background: #10b981; border-radius: 100px; }
      .badge-warn + .dom-selector ~ .bar-container .bar-fill, .badge-warn ~ .bar-container .bar-fill { background: #f59e0b; }
      .badge-expired + .dom-selector ~ .bar-container .bar-fill, .badge-expired ~ .bar-container .bar-fill { background: #ef4444; }
      .bar-legend { display: flex; justify-content: space-between; font-size: 0.78rem; color: #64748b; margin-top: -4px; font-weight: 500; }

      .card-footer-flex { border-top: 1px dashed rgba(0,0,0,0.06); padding-top: 12px; display: flex; justify-content: space-between; align-items: center; }
      .tag-pill { font-size: 0.82rem; background: rgba(0,0,0,0.04); padding: 3px 10px; border-radius: 6px; color: #475569; font-weight: 600; }
      
      .opt-group { display: flex; gap: 10px; }
      .opt-group button { background: none; font-size: 0.82rem; color: #2563eb; padding: 4px 6px; font-weight: 600; box-shadow: none; border-radius: 4px; }
      .opt-group button:hover { background: rgba(37,99,235,0.08); text-decoration: none; }
      .opt-group button.danger-link { color: #ef4444; }
      .opt-group button.danger-link:hover { background: rgba(239,68,68,0.08); }

      .win-pop { display: none; position: fixed; top:0; left:0; width:100%; height:100%; background: rgba(15, 23, 42, 0.2); backdrop-filter: blur(8px); justify-content: center; align-items: center; z-index: 9999; }
      .win-content { background: rgba(255, 255, 255, 0.95); border: 1px solid white; padding: 25px; border-radius: 18px; max-width: 420px; width: 90%; box-shadow: 0 20px 40px rgba(0,0,0,0.1); display: flex; flex-direction: column; gap: 14px; }
      .input-wrapper { display: flex; flex-direction: column; gap: 4px; }
      .input-wrapper label { font-size: 0.82rem; font-weight: 600; color: #475569; }
      .input-wrapper input, .input-wrapper select { padding: 9px 12px; border: 1px solid #cbd5e1; border-radius: 8px; outline: none; font-size: 0.92rem; background: rgba(255,255,255,0.7); }
    </style>
  </head>
  <body>
    <div id="hiddenStorage" style="display:none;">${base64Payload}</div>

    <div class="panel">
      <header>
        <div class="logo-area">
          ${config.ICON ? `<img src="${config.ICON}" class="site-avatar">` : ''}
          <h1>${config.SITENAME}</h1>
          <span class="badge">${modeBadge}</span>
        </div>
        <div class="actions-container">
          ${config.isAuthed ? `
            <button onclick="openFormModal()" class="btn-primary">➕ 添加域名</button>
            <button onclick="exportData()" class="btn-secondary">📤 导出数据</button>
            <button onclick="triggerImport()" class="btn-secondary">📥 导入数据</button>
            <button onclick="location.href='/logout'" class="btn-secondary">🔑 安全登出</button>
            <input type="file" id="importFile" style="display:none" onchange="processImport(this)">
          ` : `<button onclick="openLoginModal()" class="btn-primary">管理入口</button>`}
          ${config.BLOG_URL ? `<button onclick="window.open('${config.BLOG_URL}')" class="btn-secondary">${config.BLOG_NAME || '个人空间'}</button>` : ''}
        </div>
      </header>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">📊 总域名</div>
          <div class="stat-value">${totalCount}</div>
        </div>
        <div class="stat-card sc-ok">
          <div class="stat-label">✅ 正常</div>
          <div class="stat-value">${normalCount}</div>
        </div>
        <div class="stat-card sc-warn">
          <div class="stat-label">⚠️ 待到期</div>
          <div class="stat-value">${warningCount}</div>
        </div>
        <div class="stat-card sc-expired">
          <div class="stat-label">❌ 已到期</div>
          <div class="stat-value">${expiredCount}</div>
        </div>
      </div>

      <div class="filter-bar">
        <div class="tabs-row">
          <button class="tab-btn active" onclick="filterGroup('全部', this)">全部</button>
          <button class="tab-btn" onclick="filterGroup('一级域名', this)">一级域名</button>
          <button class="tab-btn" onclick="filterGroup('二级域名', this)">二级域名</button>
          <button class="tab-btn" onclick="filterGroup('未分组', this)">未分组</button>
          <button class="tab-btn" onclick="filterGroup('付费域名', this)">付费域名</button>
          <button class="tab-btn" onclick="filterGroup('永久免费', this)">永久免费</button>
          <button class="tab-btn" onclick="filterGroup('免费续期', this)">免费续期</button>
          <button class="tab-btn" onclick="filterGroup('到期作废', this)">到期作废</button>
        </div>
        <div class="search-box">
          <span style="position:absolute; left:10px; top:8px; color:#64748b;">🔍</span>
          <input type="text" id="searchTerm" placeholder="搜索域名..." oninput="runLocalSearch()">
        </div>
      </div>

      ${config.isAuthed && domains.length > 0 ? `
      <div class="batch-box" style="background: rgba(255,255,255,0.4); border: 1px solid rgba(255,255,255,0.3); padding: 10px 14px; border-radius:10px; margin-bottom:15px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <input type="checkbox" id="master-select" onchange="toggleSelectAll(this)" style="cursor:pointer; width:15px; height:15px;">
          <label for="master-select" style="cursor:pointer; font-size:0.88rem; margin-left:4px; font-weight:600; color:#334155;">全选当前过滤项</label>
        </div>
        <button onclick="deleteBatch()" class="tab-btn" style="background:#fee2e2; color:#ef4444; padding:5px 12px;">批量删除选中项</button>
      </div>` : ''}

      <div class="matrix-grid" id="cardMatrix">
        ${cardsHtml || '<div style="grid-column: 1/-1; text-align:center; padding:40px; color:#64748b;">暂无监控数据。</div>'}
      </div>
    </div>

    <!-- 弹窗部分 -->
    <div id="loginModal" class="win-pop">
      <div class="win-content">
        <h3>管理登录鉴权</h3>
        <div class="input-wrapper">
          <label>访问密码 (PASSWORD)</label>
          <input type="password" id="passCode" placeholder="密码">
        </div>
        <button onclick="commitLogin()" class="btn-primary" style="width:100%;">验证登录</button>
        <button onclick="closePop('loginModal')" class="btn-secondary" style="width:100%;">取消</button>
      </div>
    </div>

    <div id="domainModal" class="win-pop">
      <div class="win-content">
        <h3 id="formTitle">配置变更单</h3>
        <div class="input-wrapper"><label>域名</label><input type="text" id="fmDomain" placeholder="example.com"></div>
        <div class="input-wrapper"><label>账户标签</label><input type="text" id="fmAccount"></div>
        <div class="input-wrapper">
          <label>所属分组</label>
          <select id="fmGroup">
            <option value="未分组">未分组</option>
            <option value="付费域名">付费域名</option>
            <option value="永久免费">永久免费</option>
            <option value="免费续期">免费续期</option>
            <option value="到期作废">到期作废</option>
          </select>
        </div>
        <div class="input-wrapper">
          <label>注册服务商</label>
          <div style="display:flex; gap:6px;">
            <input type="text" id="fmRegistrar" style="flex:1;">
            <button onclick="runOnlineWhois()" class="btn-secondary" style="padding:0 10px; font-size:0.8rem;">自动获取</button>
          </div>
        </div>
        <div class="input-wrapper"><label>注册时间</label><input type="date" id="fmRegDate"></div>
        <div class="input-wrapper"><label>到期时间</label><input type="date" id="fmExpDate"></div>
        <button onclick="commitSave()" class="btn-primary" style="width:100%;">保存写入</button>
        <button onclick="closePop('domainModal')" class="btn-secondary" style="width:100%;">取消关闭</button>
      </div>
    </div>

    <script>
      let currentFilterGroup = '全部';

      function filterGroup(groupName, btn) {
        currentFilterGroup = groupName;
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        if(btn) btn.classList.add('active');
        runLocalSearch();
      }

      // 前端本地网格自识别连动搜索算法
      function runLocalSearch() {
        const query = document.getElementById('searchTerm').value.toLowerCase().trim();
        const cards = document.querySelectorAll('.js-domain-card');
        
        cards.forEach(card => {
          const domName = card.getAttribute('data-domain').toLowerCase();
          const domGroup = card.getAttribute('data-group');
          const domLevel = card.getAttribute('data-level');
          
          let matchGroup = false;
          if (currentFilterGroup === '全部') {
            matchGroup = true;
          } else if (currentFilterGroup === '一级域名' || currentFilterGroup === '二级域名') {
            matchGroup = (domLevel === currentFilterGroup);
          } else {
            matchGroup = (domGroup === currentFilterGroup);
          }
          
          const matchQuery = (!query || domName.includes(query));
          
          if(matchGroup && matchQuery) {
            card.style.display = 'flex';
          } else {
            card.style.display = 'none';
          }
        });
      }

      function openLoginModal() { document.getElementById('loginModal').style.display='flex'; }
      function closePop(id) { document.getElementById(id).style.display='none'; }
      
      async function commitLogin() {
        const password = document.getElementById('passCode').value;
        const res = await fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) });
        if (res.ok) { location.reload(); } else { alert('密码错误 ❌'); }
      }

      function openFormModal() {
        document.getElementById('formTitle').innerText = '新增域名监控';
        document.getElementById('fmDomain').disabled = false;
        document.getElementById('fmDomain').value = '';
        document.getElementById('fmAccount').value = '';
        document.getElementById('fmRegistrar').value = '';
        document.getElementById('fmRegDate').value = '';
        document.getElementById('fmExpDate').value = '';
        document.getElementById('fmGroup').value = '未分组';
        document.getElementById('domainModal').style.display = 'flex';
      }

      function editDomain(name, acct, reg, regDate, expDate, group) {
        document.getElementById('formTitle').innerText = '编辑已有节点';
        document.getElementById('fmDomain').value = name;
        document.getElementById('fmDomain').disabled = true;
        document.getElementById('fmAccount').value = acct === '无' ? '' : acct;
        document.getElementById('fmRegistrar').value = reg === '未知' ? '' : reg;
        document.getElementById('fmRegDate').value = regDate === '未知' ? '' : regDate;
        document.getElementById('fmExpDate').value = expDate === '未知' ? '' : expDate;
        document.getElementById('fmGroup').value = group;
        document.getElementById('domainModal').style.display = 'flex';
      }

      function cloneDomain(acct, reg, group) {
        openFormModal();
        document.getElementById('formTitle').innerText = '快速克隆创建';
        document.getElementById('fmAccount').value = acct === '无' ? '' : acct;
        document.getElementById('fmRegistrar').value = reg === '未知' ? '' : reg;
        document.getElementById('fmGroup').value = group;
      }

      async function runOnlineWhois() {
        const domain = document.getElementById('fmDomain').value;
        if (!domain) return alert('请输入域名后再自动探测');
        document.getElementById('fmRegistrar').value = '抓取中...';
        const res = await fetch('/api/whois/' + domain);
        if (res.ok) {
          const data = await res.json();
          document.getElementById('fmRegistrar').value = data.registrar || '';
          document.getElementById('fmRegDate').value = data.registration_date || '';
          document.getElementById('fmExpDate').value = data.expiration_date || '';
        } else {
          alert('WHOIS 解析失败，请转为手动指定。');
          document.getElementById('fmRegistrar').value = '';
        }
      }

      async function commitSave() {
        const payload = {
          domain: document.getElementById('fmDomain').value,
          account: document.getElementById('fmAccount').value,
          registrar: document.getElementById('fmRegistrar').value,
          registration_date: document.getElementById('fmRegDate').value,
          expiration_date: document.getElementById('fmExpDate').value,
          group: document.getElementById('fmGroup').value
        };
        const res = await fetch('/api/domains', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        if (res.ok) location.reload();
      }

      async function deleteSingle(domain) {
        if (confirm('确认删除针对 ' + domain + ' 的监控吗？')) {
          const res = await fetch('/api/domains/' + domain, { method: 'DELETE' });
          if (res.ok) location.reload();
        }
      }

      function toggleSelectAll(master) {
        document.querySelectorAll('.js-domain-card').forEach(card => {
          if(card.style.display !== 'none') {
            const cb = card.querySelector('.dom-selector');
            if(cb) cb.checked = master.checked;
          }
        });
      }

      async function deleteBatch() {
        const selected = Array.from(document.querySelectorAll('.dom-selector:checked')).map(cb => cb.value);
        if (selected.length === 0) return alert('请先勾选目标');
        if (confirm('确定要大容量删除选中的 ' + selected.length + ' 个监控域名吗？')) {
          for (const dom of selected) {
            await fetch('/api/domains/' + dom, { method: 'DELETE' });
          }
          location.reload();
        }
      }

      function exportData() {
        const target = document.getElementById('vaultArea');
        if (!target) return alert('读取缓存资产失败');
        const b64 = target.innerText;
        if (!b64) return alert('库中暂无可用监控数据导出');
        
        const jsonStr = decodeURIComponent(escape(window.atob(b64)));
        const localDate = new Date().toISOString().split('T')[0];
        
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'domains_backup_' + localDate + '.json';
        a.click();
      }

      function triggerImport() { document.getElementById('importFile').click(); }
      
      function processImport(input) {
        const file = input.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = async function(e) {
          try {
            const data = JSON.parse(e.target.result);
            if (!Array.isArray(data)) return alert('备份格式不匹配');
            const res = await fetch('/api/domains', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
            if (res.ok) location.reload();
          } catch(err) { alert('读取文件失败'); }
        };
        reader.readAsText(file);
      }
    </script>
  </body>
  </html>
  `;
}
