function feedEscape(value) {
  return String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}

function companyIdHex(value) {
  const text = String(value);
  const numeric = /^0x/i.test(text) ? Number.parseInt(text.slice(2), 16) : Number.parseInt(text, 10);
  return Number.isInteger(numeric) && numeric >= 0 && numeric <= 65535 ? `0x${numeric.toString(16).padStart(4, '0').toUpperCase()}` : text;
}

function companyLabel(id, names) {
  const hex = companyIdHex(id);
  return names?.[String(id)] ? `SIG company: ${names[String(id)]} · ID ${hex}` : `Unknown SIG company ID · ${hex}`;
}

function proximity(rssi) {
  if (!Number.isFinite(rssi)) return {className: 'signal-unknown', label: 'Signal unavailable'};
  if (rssi >= -55) return {className: 'signal-close', label: 'Close'};
  if (rssi >= -75) return {className: 'signal-near', label: 'Nearby'};
  return {className: 'signal-far', label: 'Weak signal'};
}

function renderWatchMatches(data) {
  const target = document.getElementById('watch-live-matches');
  const state = document.getElementById('watch-live-state');
  const freshness = [data.ble, data.wifi].filter(item => item.state !== 'disabled');
  const hasStale = freshness.some(item => item.state === 'stale');
  const hasWaiting = freshness.some(item => item.state === 'waiting');
  const sourceLabel = item => item.state === 'stale' ? `${item.name} stale` : item.state === 'waiting' ? `${item.name} waiting` : `${item.name} current`;
  const freshnessText = freshness.map((item, index) => sourceLabel({...item, name: item === data.ble ? 'BLE' : 'Wi-Fi'})).join(' · ');
  state.className = `state-tag ${hasStale ? 'stale' : hasWaiting ? 'waiting' : 'ready'}`;
  state.innerHTML = `<i></i>${feedEscape(freshnessText || 'No radio scans enabled')}`;
  if (!data.matches?.length) {
    target.innerHTML = '<p class="empty-state watch-live-empty">No saved watch rules matched the observations in memory.</p>';
    return;
  }
  target.innerHTML = data.matches.map(item => {
    const signal = Number.isFinite(item.rssi) ? `${item.rssi} dBm` : 'No signal';
    const level = proximity(item.rssi);
    const matches = item.matches.map(match => `<span class="watch-live-rule"><strong>${feedEscape(match.list_name)}</strong><small>${feedEscape(match.rule_name)}</small></span>`).join('');
    const seen = new Date(item.last_seen);
    return `<article class="watch-live-card ${level.className}">
      <div class="watch-live-card-top"><span class="watch-live-protocol">${feedEscape(item.protocol.toUpperCase())}</span><span class="proximity-label">${feedEscape(level.label)}</span></div>
      <h3>${feedEscape(item.name)}</h3>
      <div class="watch-live-signal"><strong>${feedEscape(signal)}</strong><span class="signal-meter" aria-hidden="true"><i></i></span></div>
      <p class="watch-live-address mono">${feedEscape(item.identifier)}</p>
      <div class="watch-live-rules">${matches}</div>
      <p class="watch-live-seen">Last seen <time>${Number.isNaN(seen.valueOf()) ? '—' : feedEscape(seen.toLocaleTimeString())}</time></p>
    </article>`;
  }).join('');
}

function renderFeed(scans) {
  const target = document.getElementById('feed-rows');
  document.getElementById('feed-count').textContent = `${scans.length} observation${scans.length === 1 ? '' : 's'}`;
  if (!scans.length) {
    target.innerHTML = '<tr><td colspan="4" class="empty-state">No advertisements in the memory window.</td></tr>';
    return;
  }
  target.innerHTML = [...scans].reverse().map(scan => {
    const manufacturer = Object.entries(scan.manufacturer_data || {}).map(([id, payload]) =>
      `<span class="mono">${feedEscape(companyLabel(id, scan.manufacturer_names))} · ${feedEscape(payload)}</span>`).join('<br>') || '—';
    const rssi = Number.isFinite(scan.rssi) ? `${scan.rssi} dBm` : 'Not reported';
    const seen = new Date(scan.timestamp);
    return `<tr><td><strong>${feedEscape(scan.name || 'Unnamed advertiser')}</strong></td><td class="mono">${feedEscape(rssi)}</td><td class="mono">${Number.isNaN(seen.valueOf()) ? '—' : feedEscape(seen.toLocaleTimeString())}</td><td class="feed-data">${manufacturer}</td></tr>`;
  }).join('');
}

function renderWifiObservations(observations, status) {
  const target = document.getElementById('wifi-rows');
  const state = document.getElementById('wifi-scan-state');
  if (status.scan_active) {
    state.className = 'state-tag ready';
    state.innerHTML = '<i></i>Scanning';
  } else if (status.admin_ap_active) {
    state.className = 'state-tag waiting';
    state.innerHTML = '<i></i>Admin hotspot active';
  } else {
    state.className = 'state-tag waiting';
    state.innerHTML = '<i></i>Scanning off';
  }
  if (!status.scan_active || !observations.length) {
    target.innerHTML = `<tr><td colspan="6" class="empty-state">${status.admin_ap_active ? 'Wi-Fi scanning pauses while the admin hotspot is active.' : status.scan_active ? 'No nearby networks in the latest scan.' : 'Wi-Fi scanning is off.'}</td></tr>`;
    return;
  }
  target.innerHTML = [...observations].reverse().map(item => {
    const seen = new Date(item.observed_at);
    const signal = Number.isFinite(item.signal) ? `${item.signal} dBm` : 'Not reported';
    return `<tr><td><strong>${feedEscape(item.ssid || 'Hidden network')}</strong></td><td class="mono">${feedEscape(item.bssid || '—')}</td><td class="mono">${feedEscape(signal)}</td><td class="mono">${feedEscape(item.channel ?? '—')}</td><td>${feedEscape(item.security || 'Open / unknown')}</td><td class="mono">${Number.isNaN(seen.valueOf()) ? '—' : feedEscape(seen.toLocaleTimeString())}</td></tr>`;
  }).join('');
}

async function loadFeed() {
  try {
    const responses = await Promise.all(['/api/scans', '/api/wifi/status', '/api/wifi/observations', '/api/watchlists/live'].map(url => fetch(url, { credentials: 'same-origin' })));
    if (responses.some(response => response.status === 401)) { location.href = '/login'; return; }
    if (responses.some(response => !response.ok)) throw Error('Could not read the radio window. Try refreshing.');
    const [data, wifiStatus, wifiData, watchData] = await Promise.all(responses.map(response => response.json()));
    renderFeed(data.scans || []);
    renderWifiObservations(wifiData.observations || [], wifiStatus);
    renderWatchMatches(watchData);
    const state = document.getElementById('feed-state');
    state.className = 'state-tag ready';
    state.innerHTML = '<i></i>Feed available';
    document.getElementById('feed-updated').textContent = `Updated ${new Date().toLocaleTimeString()}`;
    document.getElementById('feed-error').textContent = '';
  } catch (error) {
    document.getElementById('feed-state').className = 'state-tag error';
    document.getElementById('feed-state').textContent = 'Feed unavailable';
    document.getElementById('feed-error').textContent = error.message;
  }
}

loadFeed();
setInterval(loadFeed, 5000);
