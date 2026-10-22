const watchCsrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
let savedLists = [];
let activeList = '';
let listType = 'watch';

function watchEscape(value) { return String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])); }
function apiBase() { return listType === 'ignore' ? '/api/ignorelists' : '/api/watchlists'; }
function kindName() { return listType === 'ignore' ? 'ignore list' : 'watch list'; }
function coverageLabel(value) { return ({full: 'Full', partial: 'Partial', browser_only: 'Browser scan only', wifi_scan: 'Wi-Fi scans', disabled: 'Disabled'})[value] || 'Scan rule'; }

function prettyCriteria(criteria = {}) {
  const labels = [];
  for (const [key, label] of Object.entries({ssid_exact:'Exact SSID', ssid_contains:'SSID contains', ssid_regex:'SSID regex', bssid_exact:'Exact BSSID', observed_identifiers:'Observed address', identifier_prefixes:'MAC prefix', name_exact:'Exact name', name_contains:'Name contains', name_regex:'Name regex', manufacturer_ids:'SIG company ID', service_uuids:'Service UUID'})) {
    if (criteria[key]?.length && Array.isArray(criteria[key])) labels.push(`${label}: ${criteria[key].join(', ')}`);
    else if (criteria[key]) labels.push(`${label}: ${criteria[key]}`);
  }
  for (const key of ['bssid_prefixes','wifi_channels','wifi_security']) if (criteria[key]?.length) labels.push(`${key.replaceAll('_',' ')}: ${criteria[key].join(', ')}`);
  for (const [id, value] of Object.entries(criteria.manufacturer_data || {})) labels.push(`Manufacturer ${id}: ${typeof value === 'string' ? value : value.pattern}`);
  for (const [uuid, value] of Object.entries(criteria.service_data || {})) labels.push(`Service data ${uuid}: ${value}`);
  return labels;
}
function renderSelectedList() {
  const list = savedLists.find(item => item.name === activeList);
  if (!list) return;
  document.getElementById('selected-watchlist').textContent = list.name;
  document.getElementById('rule-count').textContent = `${list.rules.length} rule${list.rules.length === 1 ? '' : 's'} · ${listType === 'ignore' ? 'matches stay out of the live view' : 'matches appear in Monitor history'}`;
  document.getElementById('watchlist-menu').innerHTML = savedLists.map(item => `<button type="button" class="watchlist-menu-item ${item.name === activeList ? 'selected' : ''}" data-list="${watchEscape(item.name)}"><span>${watchEscape(item.name)}</span><small>${item.rules.length}</small></button>`).join('');
  document.getElementById('watch-rule-rows').innerHTML = list.rules.map(rule => {
    const criteria = prettyCriteria(rule.criteria).map(line => `<span class="criteria-line">${watchEscape(line)}</span>`).join('') || '<span class="criteria-line">No criteria</span>';
    return `<tr><td><strong class="watch-rule-name">${watchEscape(rule.label)}</strong><small class="match-mode">${watchEscape(rule.protocol.toUpperCase())} · ${watchEscape(rule.match_mode === 'any' ? 'ANY selected criterion' : 'ALL selected criteria')}</small><div class="criteria-list">${criteria}</div></td><td><span class="coverage-label coverage-${watchEscape(rule.filter_coverage)}">${coverageLabel(rule.filter_coverage)}</span></td><td><label class="rule-toggle"><input type="checkbox" data-action="enabled" data-id="${watchEscape(rule.id)}" ${rule.enabled ? 'checked' : ''}><span>${rule.enabled ? 'Enabled' : 'Paused'}</span></label></td><td><button class="text-button" type="button" data-action="delete-rule" data-id="${watchEscape(rule.id)}">Remove</button></td></tr>`;
  }).join('');
  document.querySelectorAll('[data-list]').forEach(button => button.addEventListener('click', () => { activeList = button.dataset.list; renderSelectedList(); }));
  document.querySelectorAll('[data-action="enabled"]').forEach(input => input.addEventListener('change', () => mutate(`${apiBase()}/rules/${encodeURIComponent(input.dataset.id)}/enabled`, 'POST', {enabled: input.checked})));
  document.querySelectorAll('[data-action="delete-rule"]').forEach(button => button.addEventListener('click', () => {
    if (confirm(`Remove this rule?${listType === 'watch' ? ' Existing match history will stay in Monitor.' : ''}`)) mutate(`${apiBase()}/rules/${encodeURIComponent(button.dataset.id)}`, 'DELETE');
  }));
}
function renderLists() {
  const empty = document.getElementById('watchlists-empty');
  document.getElementById('watchlists-layout').hidden = savedLists.length === 0;
  empty.hidden = savedLists.length > 0;
  document.getElementById('list-empty-title').textContent = listType === 'ignore' ? 'No ignore lists yet' : 'No watch lists yet';
  document.getElementById('list-empty-copy').textContent = listType === 'ignore' ? 'Save an observation from Devices to keep it out of the live view.' : 'Start a temporary scan in Devices, then save an observation as a rule.';
  if (!savedLists.length) return;
  if (!savedLists.some(item => item.name === activeList)) activeList = savedLists[0].name;
  renderSelectedList();
}
async function loadLists() {
  try {
    const response = await fetch(apiBase(), {credentials: 'same-origin'});
    if (response.status === 401) { location.href = '/login'; return; }
    const data = await response.json();
    if (!response.ok) throw Error(data.error || `Could not load ${kindName()}s.`);
    savedLists = data[listType === 'ignore' ? 'ignorelists' : 'watchlists'] || [];
    renderLists();
    document.getElementById('watchlists-error').textContent = '';
  } catch (error) { document.getElementById('watchlists-error').textContent = error.message; }
}
async function mutate(url, method, body) {
  try {
    const response = await fetch(url, {method, credentials: 'same-origin', headers: {'X-CSRF-Token': watchCsrf, ...(body ? {'Content-Type': 'application/json'} : {})}, ...(body ? {body: JSON.stringify(body)} : {})});
    const result = await response.json();
    if (!response.ok) throw Error(result.error || `Could not save ${kindName()} change.`);
    await loadLists();
  } catch (error) { document.getElementById('watchlists-error').textContent = error.message; }
}
document.querySelectorAll('[data-list-type]').forEach(button => button.addEventListener('click', () => {
  listType = button.dataset.listType;
  activeList = '';
  document.querySelectorAll('[data-list-type]').forEach(tab => { const selected = tab === button; tab.classList.toggle('selected', selected); tab.setAttribute('aria-selected', selected); });
  loadLists();
}));
document.getElementById('rename-watchlist').addEventListener('click', () => { const name = prompt(`New name for this ${kindName()}:`, activeList); if (name !== null) mutate(`${apiBase()}/rename`, 'POST', {old_name: activeList, new_name: name}); });
document.getElementById('delete-watchlist').addEventListener('click', () => { if (confirm(`Delete “${activeList}” and all its rules?`)) mutate(`${apiBase()}/delete`, 'POST', {name: activeList}); });
loadLists();
