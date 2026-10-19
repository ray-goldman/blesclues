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
    const responses = await Promise.all(['/api/scans', '/api/wifi/status', '/api/wifi/observations'].map(url => fetch(url, { credentials: 'same-origin' })));
    if (responses.some(response => response.status === 401)) { location.href = '/login'; return; }
    if (responses.some(response => !response.ok)) throw Error('Could not read the radio window. Try refreshing.');
    const [data, wifiStatus, wifiData] = await Promise.all(responses.map(response => response.json()));
    renderFeed(data.scans || []);
    renderWifiObservations(wifiData.observations || [], wifiStatus);
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
