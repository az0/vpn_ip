(function(){
  const state = {
    hostToResults: {},
    ipToHosts: {},
    rootDomainStats: {},
    createdUtc: null,
    analyticsSortKey: 'nxdomain_count',
    analyticsSortDir: 'desc',
  };

  function $(sel){ return document.querySelector(sel); }

  function setStatus(msg){ const el = $('#dataStatus'); if (el) el.textContent = msg; }

  function setCreatedUtc(iso){ const el = $('#createdUtc'); if (el) el.textContent = iso || 'n/a'; }

  function isIPv4(str){
    return /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/.test(str);
  }

  async function fetchJSON(url){
    const res = await fetch(url, { cache: 'no-cache' });
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    return res.json();
  }

  function buildIpToHostsFromCache(hostToResults){
    const map = {};
    for (const [host, res] of Object.entries(hostToResults)){
      if (!res || typeof res !== 'object') continue;
      const error = res.error ?? null;
      const ips = Array.isArray(res.ips) ? res.ips : [];
      if (error === null && ips.length){
        for (const ip of ips){
          if (!map[ip]) map[ip] = [];
          map[ip].push(host);
        }
      }
    }
    for (const ip in map){ map[ip].sort(); }
    return map;
  }

  function externalLinksFor(hostname, ip){
    const encHost = encodeURIComponent(hostname || '');
    const encIP = encodeURIComponent(ip || '');
    const items = [];
    if (hostname){
      items.push(`<a href="https://www.google.com/search?q=${encHost}" target="_blank" rel="noopener">Google</a>`);
      items.push(`<a href="https://ping.eu/ping/?host=${encHost}" target="_blank" rel="noopener">Ping</a>`);
    }
    if (ip){
      items.push(`<a href="https://rdap.arin.net/registry/ip/${encIP}" target="_blank" rel="noopener">RDAP</a>`);
      items.push(`<a href="https://www.shodan.io/host/${encIP}" target="_blank" rel="noopener">Shodan</a>`);
      items.push(`<a href="https://search.censys.io/hosts/${encIP}" target="_blank" rel="noopener">Censys</a>`);
      items.push(`<a href="https://pentest-tools.com/network-vulnerability-scanning/tcp-port-scanner-online?run&target=${encIP}" target="_blank" rel="noopener">Port scan</a>`);
    }
    return items.join(' · ');
  }

  function renderTable(containerSel, columns, rows){
    const el = $(containerSel);
    if (!el){ return; }
    if (!rows || rows.length === 0){
      el.innerHTML = '<div class="empty">No results</div>';
      return;
    }
    const thead = `<thead><tr>${columns.map(c=>`<th${c.sortKey?` data-sort-key="${c.sortKey}"`:''}>${c.title}</th>`).join('')}</tr></thead>`;
    const tbody = `<tbody>${rows.map(r=>`<tr>${columns.map(c=>`<td>${r[c.key] ?? ''}</td>`).join('')}</tr>`).join('')}</tbody>`;
    el.innerHTML = `<table class="data">${thead}${tbody}</table>`;
    // header click sort (analytics)
    el.querySelectorAll('th[data-sort-key]').forEach(th=>{
      th.addEventListener('click', ()=>{
        const k = th.getAttribute('data-sort-key');
        if (state.analyticsSortKey === k){
          state.analyticsSortDir = state.analyticsSortDir === 'asc' ? 'desc' : 'asc';
        } else {
          state.analyticsSortKey = k; state.analyticsSortDir = 'desc';
        }
        renderAnalytics();
      });
    });
  }

  function renderIpResults(ip){
    const hosts = state.ipToHosts[ip] || [];
    const rows = hosts.map(h=>{
      const res = state.hostToResults[h] || {};
      const ips = Array.isArray(res.ips) ? res.ips.join(', ') : '';
      const err = res.error ?? '';
      const dur = (res.dns_duration_ms != null) ? `${res.dns_duration_ms} ms` : '';
      return {
        hostname: `<span class="mono">${h}</span>`,
        ips: `<span class="mono">${ips}</span>`,
        error: err,
        dns: dur,
        tools: externalLinksFor(h, ip),
      };
    });
    const columns = [
      { key: 'hostname', title: 'Hostname' },
      { key: 'ips', title: 'Current IPs' },
      { key: 'error', title: 'Error' },
      { key: 'dns', title: 'DNS Time' },
      { key: 'tools', title: 'Tools' },
    ];
    renderTable('#ipResults', columns, rows);
  }

  function renderHostResults(host){
    const res = state.hostToResults[host];
    if (!res){
      $('#hostResults').innerHTML = `<div class="empty">No result for <span class="mono">${host}</span></div>`;
      return;
    }
    const ips = Array.isArray(res.ips) ? res.ips : [];
    const err = res.error ?? '';
    const dur = (res.dns_duration_ms != null) ? `${res.dns_duration_ms} ms` : '';

    // Associated hostnames via shared IPs
    const assoc = new Set();
    for (const ip of ips){
      const hosts = state.ipToHosts[ip] || [];
      for (const h of hosts){ if (h !== host) assoc.add(h); }
    }

    const rows = [];
    rows.push({
      label: 'Hostname', value: `<span class="mono">${host}</span>`
    });
    rows.push({
      label: 'Current IPs', value: `<span class="mono">${ips.join(', ')}</span>`
    });
    rows.push({ label: 'Error', value: err });
    rows.push({ label: 'DNS Time', value: dur });
    rows.push({ label: 'Tools', value: externalLinksFor(host, ips[0] || '') });

    const assocList = Array.from(assoc).slice(0, 100).map(h=>`<li><span class="mono">${h}</span></li>`).join('');

    $('#hostResults').innerHTML = `
      <div class="kv">
        ${rows.map(r=>`<div class="row"><div class="k">${r.label}</div><div class="v">${r.value}</div></div>`).join('')}
      </div>
      <h3>Associated hostnames via shared IPs (${assoc.size}${assoc.size>100?'+':''})</h3>
      <ul class="list">${assocList || '<li class="empty">None</li>'}</ul>
    `;
  }

  function renderAnalytics(){
    const stats = state.rootDomainStats.root_domain_stats || {};
    const items = Object.entries(stats).map(([root, s])=>({ root, ...s }));
    const k = state.analyticsSortKey;
    const dir = state.analyticsSortDir;
    items.sort((a,b)=>{
      const av = a[k] ?? 0, bv = b[k] ?? 0;
      return dir === 'asc' ? (av - bv) : (bv - av);
    });
    const top = items.slice(0, 100);
    const columns = [
      { key: 'root', title: 'Root Domain', sortKey: 'root' },
      { key: 'host_count', title: 'Hosts', sortKey: 'host_count' },
      { key: 'success_count', title: 'Success', sortKey: 'success_count' },
      { key: 'total_error_count', title: 'Errors', sortKey: 'total_error_count' },
      { key: 'nxdomain_count', title: 'NXDOMAIN', sortKey: 'nxdomain_count' },
      { key: 'timeout_count', title: 'Timeout', sortKey: 'timeout_count' },
    ];
    renderTable('#analytics', columns, top.map(s=>({
      root: `<span class="mono">${s.root}</span>`,
      host_count: s.host_count,
      success_count: s.success_count,
      total_error_count: s.total_error_count,
      nxdomain_count: s.nxdomain_count,
      timeout_count: s.timeout_count,
    })));
  }

  function filterHostEntry(host, res, options){
    const ips = Array.isArray(res.ips) ? res.ips : [];
    const error = res.error ?? null;
    if (options.onlyActive){
      return error === null && ips.length > 0;
    }
    if (!options.includeErrors){
      return error === null && ips.length > 0;
    }
    return true;
  }

  function download(filename, text){
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  }

  function onDownloadCSV(){
    const includeErrors = $('#dlIncludeErrors').checked;
    const onlyActive = $('#dlOnlyActive').checked;
    const rows = [];
    rows.push(['hostname','ips','error','dns_duration_ms'].join(','));
    for (const [host, res] of Object.entries(state.hostToResults)){
      if (!filterHostEntry(host, res, { includeErrors, onlyActive })) continue;
      const ips = Array.isArray(res.ips) ? res.ips.join(';') : '';
      const err = res.error ?? '';
      const dns = res.dns_duration_ms ?? '';
      rows.push([host, ips, err, dns].map(v=>String(v).replaceAll('"','""')).map(v=>`"${v}"`).join(','));
    }
    download('vpnip.csv', rows.join('\n'));
  }

  function onDownloadHosts(){
    const includeErrors = $('#dlIncludeErrors').checked;
    const onlyActive = $('#dlOnlyActive').checked;
    const lines = [];
    lines.push(`# Generated ${new Date().toISOString()}`);
    for (const [host, res] of Object.entries(state.hostToResults)){
      if (!filterHostEntry(host, res, { includeErrors, onlyActive })) continue;
      lines.push(`0.0.0.0 ${host}`);
    }
    download('hosts.txt', lines.join('\n'));
  }

  function wireEvents(){
    $('#ipSearchBtn').addEventListener('click', ()=>{
      const ip = $('#ipInput').value.trim();
      if (!isIPv4(ip)){
        renderTable('#ipResults', [], []);
        $('#ipResults').innerHTML = '<div class="empty">Enter a valid IPv4 address</div>';
        return;
      }
      renderIpResults(ip);
    });
    $('#hostSearchBtn').addEventListener('click', ()=>{
      const host = $('#hostInput').value.trim().toLowerCase();
      if (!host){
        $('#hostResults').innerHTML = '<div class="empty">Enter a hostname</div>';
        return;
      }
      renderHostResults(host);
    });
    $('#dlCsvBtn').addEventListener('click', onDownloadCSV);
    $('#dlHostsBtn').addEventListener('click', onDownloadHosts);
  }

  async function init(){
    try {
      setStatus('Loading data…');
      const p1 = fetchJSON('./ip_cache.json');
      const p2 = fetchJSON('./ip_to_hostnames.json').catch(()=>null);
      const p3 = fetchJSON('./root_domain_stats.json').catch(()=>({ root_domain_stats: {} }));
      const [cache, ipIndex, rootStats] = await Promise.all([p1, p2, p3]);

      state.hostToResults = cache.host_to_results || {};
      state.createdUtc = cache.created_utc || null;
      state.rootDomainStats = rootStats || { root_domain_stats: {} };

      if (ipIndex && ipIndex.ip_to_hostnames){
        state.ipToHosts = ipIndex.ip_to_hostnames;
      } else {
        state.ipToHosts = buildIpToHostsFromCache(state.hostToResults);
      }

      setCreatedUtc(state.createdUtc);
      const hostCount = Object.keys(state.hostToResults).length;
      const ipCount = Object.keys(state.ipToHosts).length;
      setStatus(`Loaded ${hostCount.toLocaleString()} hostnames across ${ipCount.toLocaleString()} IPs`);

      wireEvents();
      renderAnalytics();
    } catch (e){
      console.error(e);
      setStatus(`Failed to load data: ${e.message}`);
    }
  }

  document.addEventListener('DOMContentLoaded', init);
})();
