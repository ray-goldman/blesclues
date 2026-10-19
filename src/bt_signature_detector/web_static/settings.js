const form = document.getElementById('settings');
const result = document.getElementById('result');
const token = document.querySelector('meta[name="csrf-token"]').content;
const prefixList = document.getElementById('prefix-list');
let saved = {};

function settingsEscape(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}

async function loadBuiltinRules() {
  const target = document.getElementById('builtin-rules');
  try {
    const response = await fetch('/api/detections/rules');
    if (!response.ok) throw Error('Built-in rules are unavailable.');
    const data = await response.json();
    const policy = data.scoring;
    document.getElementById('score-policy').textContent = `Alert threshold ${policy.alert_threshold} · cross-radio bonus ${policy.correlation_bonus} within ${policy.correlation_window_seconds}s`;
    target.innerHTML = data.rules.map(rule => `<tr><td>${settingsEscape(rule.protocol.toUpperCase())}</td><td><strong>${settingsEscape(rule.vendor)}</strong></td><td>${settingsEscape(rule.match_type)}</td><td class="mono feed-data">${settingsEscape(rule.pattern)}</td><td class="mono">${Number(rule.score)}</td><td>${settingsEscape([rule.source, rule.notes].filter(Boolean).join(' · ') || rule.relevance || '—')}</td></tr>`).join('');
  } catch {
    target.innerHTML = '<tr><td colspan="6" class="empty-state">Built-in rules could not be loaded.</td></tr>';
  }
}

function addPrefixRow(pattern = {}) {
  const row = document.createElement('div');
  row.className = 'prefix-row';
  row.dataset.prefixRow = '';

  const fields = [
    ['Offset', 'start_position', pattern.start_position ?? 0, 0, 255],
    ['AD type', 'ad_data_type', pattern.ad_data_type ?? 255, 1, 255],
    ['Hex prefix', 'pattern', (pattern.pattern || '').toUpperCase(), null, null],
  ];
  for (const [labelText, name, value, min, max] of fields) {
    const label = document.createElement('label');
    label.className = 'field';
    label.append(document.createTextNode(labelText));
    const input = document.createElement('input');
    input.dataset.prefixField = name;
    input.name = `prefix_${name}`;
    input.value = value;
    input.required = true;
    if (name === 'pattern') {
      input.type = 'text';
      input.maxLength = 510;
      input.pattern = '(?:[0-9A-Fa-f]{2})+';
      input.autocomplete = 'off';
      input.spellcheck = false;
      input.placeholder = 'e.g. A1B2C3';
    } else {
      input.type = 'number';
      input.min = min;
      input.max = max;
      input.step = 1;
    }
    label.append(input);
    row.append(label);
  }

  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'remove-prefix';
  remove.textContent = 'Remove';
  remove.setAttribute('aria-label', 'Remove this filter prefix');
  row.append(remove);
  prefixList.append(row);
  syncRemoveButtons();
}

function syncRemoveButtons() {
  const rows = [...prefixList.querySelectorAll('[data-prefix-row]')];
  for (const row of rows) row.querySelector('.remove-prefix').disabled = rows.length < 2;
}

function renderPrefixes(patterns) {
  prefixList.replaceChildren();
  for (const pattern of patterns) addPrefixRow(pattern);
}

function readPrefixes() {
  return [...prefixList.querySelectorAll('[data-prefix-row]')].map(row => ({
    start_position: Number(row.querySelector('[data-prefix-field="start_position"]').value),
    ad_data_type: Number(row.querySelector('[data-prefix-field="ad_data_type"]').value),
    pattern: row.querySelector('[data-prefix-field="pattern"]').value.trim().toLowerCase(),
  }));
}

async function loadSettings() {
  try {
    const [settingsResponse, statusResponse] = await Promise.all([fetch('/api/settings'), fetch('/api/status')]);
    if (!settingsResponse.ok) throw Error('Unable to load configuration');
    const config = await settingsResponse.json();
    const status = statusResponse.ok ? await statusResponse.json() : {};
    saved = config;
    for (const name of ['global_min_rssi', 'cooldown_seconds', 'min_observations', 'manifest_url', 'ssid', 'channel']) {
      if (config[name] !== null && config[name] !== undefined) form.elements[name].value = config[name];
    }
    form.elements.access_point_enabled.checked = Boolean(config.access_point_enabled);
    form.elements.wifi_scanning_enabled.checked = Boolean(config.wifi_scanning_enabled);
    renderPrefixes(config.or_patterns || []);
    document.getElementById('ap-state').textContent = status.access_point ? 'Network is active.' : 'Network is off.';
    const mode = config.wifi_mode || 'idle';
    document.getElementById('wifi-mode-state').textContent = mode === 'scan'
      ? 'Nearby Wi-Fi scanning is enabled; the hidden hotspot is off.'
      : mode === 'admin_ap' ? 'The hidden hotspot is enabled; nearby Wi-Fi scanning is off.'
        : 'The Wi-Fi radio is idle.';
  } catch {
    result.textContent = 'Unable to load configuration.';
  }
}

document.getElementById('add-prefix').addEventListener('click', () => addPrefixRow());
form.elements.wifi_scanning_enabled.addEventListener('change', () => {
  if (form.elements.wifi_scanning_enabled.checked) form.elements.access_point_enabled.checked = false;
});
form.elements.access_point_enabled.addEventListener('change', () => {
  if (form.elements.access_point_enabled.checked) form.elements.wifi_scanning_enabled.checked = false;
});
prefixList.addEventListener('click', event => {
  if (!event.target.matches('.remove-prefix') || event.target.disabled) return;
  event.target.closest('[data-prefix-row]').remove();
  syncRemoveButtons();
});

form.addEventListener('submit', async event => {
  event.preventDefault();
  const data = {};
  for (const key of ['global_min_rssi', 'cooldown_seconds', 'min_observations']) {
    const raw = form.elements[key].value;
    const value = raw === '' ? null : Number(raw);
    if (value !== saved[key]) data[key] = value;
  }
  const manifest = form.elements.manifest_url.value || null;
  if (manifest !== saved.manifest_url) data.manifest_url = manifest;
  const enabled = form.elements.access_point_enabled.checked;
  const wifiScanning = form.elements.wifi_scanning_enabled.checked;
  const ssid = form.elements.ssid.value.trim();
  const channel = Number(form.elements.channel.value);
  if (enabled !== Boolean(saved.access_point_enabled)) data.access_point_enabled = enabled;
  if (wifiScanning !== Boolean(saved.wifi_scanning_enabled)) data.wifi_scanning_enabled = wifiScanning;
  if (ssid !== saved.ssid) data.ssid = ssid;
  if (channel !== saved.channel) data.channel = channel;
  const passphrase = form.elements.passphrase.value;
  if (passphrase) data.passphrase = passphrase;
  const patterns = readPrefixes();
  if (JSON.stringify(patterns) !== JSON.stringify(saved.or_patterns || [])) data.or_patterns = patterns;
  if (!Object.keys(data).length) {
    result.textContent = 'No changes to save.';
    return;
  }
  if (!form.reportValidity()) return;
  result.textContent = 'Saving…';
  try {
    const response = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
      body: JSON.stringify(data),
    });
    const body = await response.json();
    if (!response.ok) throw Error(body.error || 'Settings were rejected');
    result.textContent = data.wifi_scanning_enabled !== undefined || data.access_point_enabled !== undefined
      ? 'Wi-Fi radio mode changed.' : data.or_patterns ? 'Filters saved; scanner restarted.' : 'Settings saved.';
    form.elements.passphrase.value = '';
    await loadSettings();
  } catch (error) {
    result.textContent = error.message;
  }
});

const password = document.getElementById('password');
password.addEventListener('submit', async event => {
  event.preventDefault();
  const body = new URLSearchParams(new FormData(password));
  try {
    const response = await fetch('/password', {
      method: 'POST',
      headers: { 'X-CSRF-Token': token, 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    document.getElementById('password-result').textContent = response.ok ? 'UI password changed' : await response.text();
    if (response.ok) password.reset();
  } catch {
    document.getElementById('password-result').textContent = 'Unable to change password';
  }
});

loadSettings();
loadBuiltinRules();
