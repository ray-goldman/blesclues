const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
let currentDevices = [];
let currentWifiDevices = [];
let watchOptions = [];
let watchProtocol = 'ble';
let pausedInventory = false;

function text(id, value) {
  const element = document.getElementById(id);
  if (element) element.textContent = value ?? '—';
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? '—' : date.toLocaleTimeString();
}

function renderWifiDevices(observations, status) {
  const target = document.getElementById('wifi-device-cards');
  const state = document.getElementById('wifi-device-state');
  const note = document.getElementById('wifi-device-note');
  if (!target || !state || !note) return;

  if (pausedInventory) {
    state.className = 'state-tag waiting';
    state.innerHTML = '<i></i>Paused';
    note.textContent = 'Showing the Wi-Fi networks seen before the scan was paused. Resume the device scan to refresh results.';
    return;
  }

  if (status.scan_active) {
    state.className = 'state-tag ready';
    state.innerHTML = '<i></i>Scanning';
    note.textContent = `Wi-Fi scanning is enabled. Results refresh about every ${status.scan_interval_seconds || 15} seconds and stay in temporary memory.`;
  } else if (status.admin_ap_active) {
    state.className = 'state-tag waiting';
    state.innerHTML = '<i></i>Admin hotspot active';
    note.textContent = 'Wi-Fi scanning is paused while the hidden admin hotspot is active.';
  } else {
    state.className = 'state-tag waiting';
    state.innerHTML = '<i></i>Scanning off';
    note.textContent = 'Enable nearby Wi-Fi scans in Settings to list networks here. The hidden admin hotspot and Wi-Fi scanning cannot run at the same time.';
  }

  if (!status.scan_active || !observations.length) {
    const message = status.admin_ap_active
      ? 'Wi-Fi scanning pauses while the admin hotspot is active.'
      : status.scan_active ? 'No nearby networks in the latest scan.' : 'Wi-Fi scanning is off.';
    target.innerHTML = `<p class="empty-state">${escapeHtml(message)}</p>`;
    return;
  }

  currentWifiDevices = [...observations]
    .sort((left, right) => String(right.observed_at).localeCompare(String(left.observed_at)));
  target.innerHTML = currentWifiDevices.map((item, index) => {
      const signal = Number.isFinite(item.signal) ? `${item.signal} dBm` : 'Not reported';
      return `<article class="wifi-device-card">
        <div class="wifi-card-heading"><p class="kicker">WI-FI NETWORK</p><strong>${escapeHtml(item.ssid || 'Hidden network')}</strong></div>
        <dl><div><dt>BSSID</dt><dd class="mono">${escapeHtml(item.bssid || '—')}</dd></div><div><dt>Signal</dt><dd class="mono">${escapeHtml(signal)}</dd></div>
          <div><dt>Channel</dt><dd class="mono">${escapeHtml(item.channel ?? '—')}</dd></div><div><dt>Security</dt><dd>${escapeHtml(item.security || 'Open / unknown')}</dd></div>
          <div><dt>Last seen</dt><dd class="mono">${escapeHtml(formatTime(item.observed_at))}</dd></div></dl>
        <button type="button" class="text-button" data-wifi-watch-index="${index}">Watch this network</button>
      </article>`;
    }).join('');
  target.querySelectorAll('[data-wifi-watch-index]').forEach(button => button.addEventListener('click', () => openWatchDialog(currentWifiDevices[Number(button.dataset.wifiWatchIndex)], 'wifi')));
}

async function loadWifiDevices() {
  try {
    const [statusResponse, observationsResponse] = await Promise.all([
      fetch('/api/wifi/status', {credentials: 'same-origin'}),
      fetch('/api/wifi/observations', {credentials: 'same-origin'})
    ]);
    if (statusResponse.status === 401 || observationsResponse.status === 401) { location.href = '/login'; return; }
    if (!statusResponse.ok || !observationsResponse.ok) throw Error('Could not read Wi-Fi scan results.');
    const [status, result] = await Promise.all([statusResponse.json(), observationsResponse.json()]);
    renderWifiDevices(result.observations || [], status);
  } catch (error) {
    const state = document.getElementById('wifi-device-state');
    const rows = document.getElementById('wifi-device-cards');
    if (state) {
      state.className = 'state-tag error';
      state.textContent = 'Wi-Fi status unavailable';
    }
    if (rows) rows.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  }
}

function setActionError(message) {
  const panel = document.getElementById('device-action-error');
  panel.hidden = !message;
  text('device-action-error-text', message || '');
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

function renderDevices(devices) {
  currentDevices = devices;
  const target = document.getElementById('device-rows');
  text('device-count', devices.length);
  if (!devices.length) {
    target.innerHTML = '<tr class="empty-row"><td colspan="9" class="empty-state">No advertisers in the current memory window.</td></tr>';
    return;
  }
  target.innerHTML = [...devices].sort((left, right) => String(right.last_seen).localeCompare(String(left.last_seen))).map(device => {
    const manufacturer = Object.entries(device.manufacturer_data || {}).map(([company, bytes]) =>
      `${escapeHtml(companyLabel(company, device.manufacturer_names))} · ${escapeHtml(bytes)}`).join('<br>') || '—';
    const uuids = (device.service_uuids || []).map(escapeHtml).join('<br>') || '—';
    const serviceData = Object.entries(device.service_data || {}).map(([uuid, bytes]) => `${escapeHtml(uuid)} · ${escapeHtml(bytes)}`).join('<br>') || '—';
    const addressType = device.address_type ? `<small>${escapeHtml(device.address_type)}</small>` : '';
    const signal = Number.isFinite(device.rssi) ? `${escapeHtml(device.rssi)} dBm` : 'Not reported';
    return `<tr>
      <td data-label="Device"><strong>${escapeHtml(device.name || 'Unnamed device')}</strong></td>
      <td data-label="Observed address" class="mono address-cell">${escapeHtml(device.identifier || 'Unknown')}${addressType}</td>
      <td data-label="Signal" class="mono">${signal}</td>
      <td data-label="First seen" class="mono">${escapeHtml(formatTime(device.first_seen))}</td>
      <td data-label="Last seen" class="mono">${escapeHtml(formatTime(device.last_seen))}</td>
      <td data-label="Manufacturer data" class="mono data-cell">${manufacturer}</td>
      <td data-label="Service UUIDs" class="mono data-cell">${uuids}</td>
      <td data-label="Service data" class="mono data-cell">${serviceData}</td>
      <td data-label="Watch rule"><button type="button" class="text-button" data-watch-index="${devices.indexOf(device)}">Watch this</button></td>
    </tr>`;
  }).join('');
  target.querySelectorAll('[data-watch-index]').forEach(button => button.addEventListener('click', () => openWatchDialog(currentDevices[Number(button.dataset.watchIndex)])));
}

function openWatchDialog(device, protocol = 'ble') {
  if (!device) return;
  watchProtocol = protocol;
  const options = [];
  if (protocol === 'wifi') {
    if (device.ssid) options.push({kind: 'ssid', value: device.ssid, label: `SSID “${device.ssid}”`, checked: true});
    if (device.bssid) {
      options.push({kind: 'bssid_exact', value: device.bssid, label: `Exact BSSID ${device.bssid}`, checked: false});
      const octets = device.bssid.split(':');
      if (octets.length === 6 && octets.slice(0, 3).every(value => /^[0-9a-f]{2}$/i.test(value)))
        options.push({kind: 'bssid_prefix', value: octets.slice(0, 3).join(':'), label: `BSSID prefix ${octets.slice(0, 3).join(':')}`, checked: false});
    }
    if (device.channel) options.push({kind: 'wifi_channel', value: device.channel, label: `Channel ${device.channel}`, checked: false});
    options.push({kind: 'wifi_security', value: device.security || 'Open / unknown', label: `Security: ${device.security || 'Open / unknown'}`, checked: false});
  } else {
  if (device.identifier) {
    options.push({kind: 'observed_identifiers', value: device.identifier, label: `Exact observed address ${device.identifier}`, checked: false});
    const octets = device.identifier.split(/[:-]/);
    if (octets.length >= 3 && octets.slice(0, 3).every(value => /^[0-9a-f]{2}$/i.test(value))) {
      options.push({kind: 'identifier_prefix', value: octets.slice(0, 3).join(':'), label: `MAC prefix ${octets.slice(0, 3).join(':')}`, checked: true});
    }
  }
  if (device.name) options.push({kind: 'name_exact', value: device.name, label: `Exact advertised name “${device.name}”`});
  for (const [company, payload] of Object.entries(device.manufacturer_data || {})) {
    options.push({kind: 'manufacturer_id', key: company, label: `SIG company ID · ${companyLabel(company, device.manufacturer_names)}`});
    options.push({kind: 'manufacturer_data', key: company, value: payload, label: `${companyLabel(company, device.manufacturer_names)} · prefix ${payload}`});
  }
  for (const uuid of device.service_uuids || []) options.push({kind: 'service_uuids', value: uuid, label: `Advertised service ${uuid}`});
  for (const [uuid, payload] of Object.entries(device.service_data || {})) options.push({kind: 'service_data', key: uuid, value: payload, label: `Service data ${uuid} · prefix ${payload}`});
  }
  watchOptions = options;
  const criteria = document.getElementById('watch-criteria-options');
  criteria.innerHTML = options.map((item, index) => {
    const controls = item.kind === 'manufacturer_data' || item.kind === 'service_data'
      ? `<label class="field prefix-choice">Payload prefix (hex)<input class="watch-prefix" value="${escapeHtml(item.value)}" maxlength="64" pattern="[a-fA-F0-9 ]+" required></label>`
      : item.kind === 'identifier_prefix'
        ? '<label class="field prefix-choice">Match first<select class="watch-address-octets"><option value="1">1 octet</option><option value="2">2 octets</option><option value="3" selected>3 octets</option></select></label>'
      : item.kind === 'name_exact'
        ? `<label class="field prefix-choice">Name pattern<input class="watch-name-pattern" value="${escapeHtml(item.value)}" maxlength="248" required></label><label class="field prefix-choice">Name match<select class="watch-name-mode"><option value="exact">Exact</option><option value="contains">Contains</option><option value="regex">Regular expression</option></select><span class="field-note">Nested or ambiguous repeated groups are rejected to keep scans responsive.</span></label>`
      : item.kind === 'ssid'
        ? `<label class="field prefix-choice">SSID pattern<input class="watch-ssid-pattern" value="${escapeHtml(item.value)}" maxlength="32" required></label><label class="field prefix-choice">SSID match<select class="watch-ssid-mode"><option value="exact">Exact</option><option value="contains">Contains</option><option value="regex">Regular expression</option></select><span class="field-note">Nested or ambiguous repeated groups are rejected to keep scans responsive.</span></label>`
      : item.kind === 'bssid_prefix'
        ? '<label class="field prefix-choice">Match first<select class="watch-address-octets"><option value="1">1 octet</option><option value="2">2 octets</option><option value="3" selected>3 octets</option></select></label>'
        : '';
    return `<div class="watch-option"><label><input type="checkbox" data-watch-kind="${escapeHtml(item.kind)}" data-watch-index="${index}" ${item.checked === false ? '' : 'checked'}><span>${escapeHtml(item.label)}</span></label>${controls}</div>`;
  }).join('') || '<p class="empty-state">No matching characteristics were observed.</p>';
  document.getElementById('watch-dialog-title').textContent = protocol === 'wifi' ? 'Watch this network' : 'Watch this device';
  document.getElementById('watch-address-note').textContent = protocol === 'wifi'
    ? 'SSID rules can match network names. BSSID rules use the access point address, which may change.'
    : device.identifier ? `Address ${device.identifier} can rotate. An address rule only matches this exact observed identifier.` : '';
  const form = document.getElementById('watch-rule-form');
  form.elements.label.value = protocol === 'wifi' ? device.ssid || 'Wi-Fi network' : device.name || 'BLE device';
  form.elements.list_name.value = '';
  form.elements.match_mode.value = 'all';
  document.getElementById('watch-form-error').textContent = '';
  document.getElementById('watch-dialog').showModal();
  loadExistingWatchLists();
}

async function loadExistingWatchLists() {
  try {
    const response = await fetch('/api/watchlists', {credentials: 'same-origin'});
    if (!response.ok) return;
    const result = await response.json();
    document.getElementById('watch-list-options').innerHTML = (result.watchlists || []).map(item => `<option value="${escapeHtml(item.name)}"></option>`).join('');
  } catch (_) { /* Saving a new list remains available if the list lookup is offline. */ }
}

document.getElementById('close-watch').addEventListener('click', () => document.getElementById('watch-dialog').close());
document.getElementById('cancel-watch').addEventListener('click', () => document.getElementById('watch-dialog').close());
document.getElementById('watch-rule-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const body = {label: form.elements.label.value.trim(), list_name: form.elements.list_name.value.trim(), match_mode: form.elements.match_mode.value};
  if (watchProtocol === 'wifi') body.protocol = 'wifi';
  const selected = [...document.querySelectorAll('#watch-criteria-options input:checked')];
  if (selected.filter(item => item.dataset.watchKind === 'manufacturer_data').length > 1) {
    document.getElementById('watch-form-error').textContent = 'A rule can use one manufacturer company ID. Save separate rules for additional IDs.';
    return;
  }
  for (const checkbox of selected) {
    const option = currentWatchOptions()[Number(checkbox.dataset.watchIndex)];
    if (!option) continue;
    const row = checkbox.closest('.watch-option');
    if (option.kind === 'ssid') {
      const mode = row.querySelector('.watch-ssid-mode')?.value || 'exact';
      const value = row.querySelector('.watch-ssid-pattern')?.value.trim();
      if (!value) { document.getElementById('watch-form-error').textContent = 'Enter an SSID pattern.'; return; }
      body[mode === 'contains' ? 'ssid_contains' : mode === 'regex' ? 'ssid_regex' : 'ssid_exact'] = value;
    }
    else if (option.kind === 'bssid_exact') body.bssid_exact = option.value;
    else if (option.kind === 'bssid_prefix') {
      const octets = Number(row.querySelector('.watch-address-octets')?.value || 3);
      body.bssid_prefixes = [...(body.bssid_prefixes || []), option.value.split(':').slice(0, octets).join(':')];
    }
    else if (option.kind === 'wifi_channel') body.wifi_channels = [...(body.wifi_channels || []), Number(option.value)];
    else if (option.kind === 'wifi_security') body.wifi_security = [...(body.wifi_security || []), option.value];
    else if (option.kind === 'observed_identifiers') body.observed_identifiers = [...(body.observed_identifiers || []), option.value];
    else if (option.kind === 'name_exact') {
      const mode = row.querySelector('.watch-name-mode')?.value || 'exact';
      const namePattern = row.querySelector('.watch-name-pattern')?.value.trim();
      if (!namePattern) {
        document.getElementById('watch-form-error').textContent = 'Enter a name pattern.';
        return;
      }
      body[mode === 'contains' ? 'name_contains' : mode === 'regex' ? 'name_regex' : 'name_exact'] = namePattern;
    }
    else if (option.kind === 'identifier_prefix') {
      const octets = Number(row.querySelector('.watch-address-octets')?.value || 3);
      body.identifier_prefixes = [...(body.identifier_prefixes || []), option.value.split(':').slice(0, octets).join(':')];
    }
    else if (option.kind === 'manufacturer_id') {
      const rawId = String(option.key);
      const numeric = /^0x/i.test(rawId) ? Number.parseInt(rawId.slice(2), 16) : Number.parseInt(rawId, 10);
      if (Number.isInteger(numeric)) body.manufacturer_ids = [...(body.manufacturer_ids || []), numeric];
    }
    else if (option.kind === 'manufacturer_data' || option.kind === 'service_data') {
      const prefix = row.querySelector('.watch-prefix')?.value.trim();
      if (!prefix || !/^(?:[a-fA-F0-9]{2}\s*)+$/.test(prefix)) {
        document.getElementById('watch-form-error').textContent = 'Manufacturer prefixes must contain complete hexadecimal bytes.';
        return;
      }
      if (option.kind === 'manufacturer_data') body.manufacturer_data = {...body.manufacturer_data, [option.key]: prefix.replace(/\s+/g, '')};
      else body.service_data = {...body.service_data, [option.key]: prefix.replace(/\s+/g, '')};
    }
    else if (option.kind === 'service_uuids') body.service_uuids = [...(body.service_uuids || []), option.value];
  }
  if (!Object.keys(body).some(key => ['observed_identifiers', 'identifier_prefixes', 'name_exact', 'name_contains', 'name_regex', 'manufacturer_data', 'manufacturer_ids', 'service_uuids', 'service_data', 'ssid_exact', 'ssid_contains', 'ssid_regex', 'bssid_exact', 'bssid_prefixes', 'wifi_channels', 'wifi_security'].includes(key))) {
    document.getElementById('watch-form-error').textContent = 'Select at least one observed characteristic.';
    return;
  }
  try {
    const response = await fetch('/api/watchlists/rules', {method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, body: JSON.stringify(body)});
    const result = await response.json();
    if (!response.ok) throw Error(result.error || 'Could not save this watch rule.');
    document.getElementById('watch-dialog').close();
    text('devices-error', `Saved “${result.rule.label}” to ${result.rule.watchlist_name || body.list_name}.`);
    await loadDevices();
  } catch (error) {
    document.getElementById('watch-form-error').textContent = error.message;
  }
});

function currentWatchOptions() { return watchOptions; }

function showScannerStatus(status) {
  const active = Boolean(status.browser_active);
  const state = document.getElementById('browser-state');
  const health = status.scanner_state || 'unknown';
  const failed = health === 'error' || status.scanner === 'failed';
  state.className = `state-tag ${failed ? 'error' : active && health === 'scanning' ? 'ready' : 'waiting'}`;
  state.innerHTML = `<i></i>${failed ? 'Scanner error' : pausedInventory ? 'Scan paused' : active && health === 'scanning' ? 'Broad scan running' : active ? 'Starting broad scan' : 'Filtered scan mode'}`;
  text('browser-mode', pausedInventory ? 'Paused · resume to continue' : active ? 'Temporary broad scan' : 'Configured scan filters');
  text('scanner-service', status.scanner || 'unknown');
  text('scanner-health', health);
  text('saved-mode', status.configured_scan_mode || 'unknown');
  text('scanner-error', status.scanner_error || '');
  const start = document.getElementById('start-browser');
  start.textContent = pausedInventory ? 'Resume scan' : 'Start device scan';
  start.disabled = active;
  document.getElementById('pause-browser').disabled = !active;
  document.getElementById('stop-browser').disabled = !active && !pausedInventory;
}

async function loadDevices() {
  try {
    const [statusResponse, devicesResponse] = await Promise.all([
      fetch('/api/devices/status', { credentials: 'same-origin' }),
      fetch('/api/devices', { credentials: 'same-origin' })
    ]);
    if (statusResponse.status === 401 || devicesResponse.status === 401) { location.href = '/login'; return; }
    if (!statusResponse.ok || !devicesResponse.ok) throw Error('Could not read device scan status. Try refreshing.');
    const [status, result] = await Promise.all([statusResponse.json(), devicesResponse.json()]);
    showScannerStatus(status);
    if (!pausedInventory) renderDevices(result.devices || []);
    text('browser-updated', `Updated ${new Date().toLocaleTimeString()}`);
  } catch (error) {
    text('devices-error', error.message);
  }
}

async function setBrowserMode(action) {
  const start = document.getElementById('start-browser');
  const pause = document.getElementById('pause-browser');
  const stop = document.getElementById('stop-browser');
  start.disabled = pause.disabled = stop.disabled = true;
  const endpoint = action === 'pause' ? 'stop' : action === 'resume' ? 'start' : action;
  try {
    const response = await fetch(`/api/devices/${endpoint}`, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'X-CSRF-Token': csrf }
    });
    const result = await response.json();
    if (!response.ok) throw Error(result.error || 'Could not change scan mode.');
    pausedInventory = action === 'pause';
    if (action === 'stop' || action === 'resume') renderDevices([]);
    showScannerStatus(result);
    setActionError(result.ok ? '' : 'The scanner did not enter the requested mode. Check its status before continuing.');
  } catch (error) {
    setActionError(error.message);
  } finally {
    await loadDevices();
  }
}

document.getElementById('start-browser').addEventListener('click', () => setBrowserMode(pausedInventory ? 'resume' : 'start'));
document.getElementById('pause-browser').addEventListener('click', () => setBrowserMode('pause'));
document.getElementById('stop-browser').addEventListener('click', () => setBrowserMode('stop'));
document.getElementById('dismiss-device-error').addEventListener('click', () => setActionError(''));
loadDevices();
setInterval(loadDevices, 2000);
loadWifiDevices();
setInterval(loadWifiDevices, 5000);
