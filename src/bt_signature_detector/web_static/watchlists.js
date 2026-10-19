const watchCsrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
let savedLists = [];
let activeList = '';

function watchEscape(value) {
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

function prettyCriteria(criteria, manufacturerNames = {}) {
  const labels = [];
  if (criteria.observed_identifiers?.length) labels.push(`Observed address ${criteria.observed_identifiers.join(', ')}`);
  if (criteria.identifier_prefixes?.length) labels.push(`MAC prefix ${criteria.identifier_prefixes.join(', ')}`);
  if (criteria.name_exact) labels.push(`Exact name “${criteria.name_exact}”`);
  if (criteria.name_contains) labels.push(`Name contains “${criteria.name_contains}”`);
  if (criteria.name_regex) labels.push(`Name regex /${criteria.name_regex}/`);
  if (criteria.manufacturer_ids?.length) labels.push(`SIG company ID ${criteria.manufacturer_ids.map(id => companyLabel(id, manufacturerNames)).join(', ')}`);
  for (const [company, value] of Object.entries(criteria.manufacturer_data || {})) {
    labels.push(`${companyLabel(company, manufacturerNames)} · ${typeof value === 'string' ? value : value.pattern}`);
  }
  if (criteria.service_uuids?.length) labels.push(`Service UUID ${criteria.service_uuids.join(', ')}`);
  for (const [uuid, prefix] of Object.entries(criteria.service_data || {})) labels.push(`Service data ${uuid} · ${prefix}`);
  return labels;
}

function coverageLabel(value, enabled) {
  if (!enabled || value === 'disabled') return 'Disabled';
  return ({full: 'Full', partial: 'Partial', browser_only: 'Browser scan only'})[value] || 'Browser scan only';
}

function renderSelectedList() {
  const list = savedLists.find(item => item.name === activeList);
  if (!list) return;
  document.getElementById('selected-watchlist').textContent = list.name;
  document.getElementById('rule-count').textContent = `${list.rules.length} rule${list.rules.length === 1 ? '' : 's'} · matches appear in Monitor history`;
  document.getElementById('watchlist-menu').innerHTML = savedLists.map(item =>
    `<button type="button" class="watchlist-menu-item ${item.name === activeList ? 'selected' : ''}" data-list="${watchEscape(item.name)}"><span>${watchEscape(item.name)}</span><small>${item.rules.length}</small></button>`).join('');
  document.getElementById('watch-rule-rows').innerHTML = list.rules.map(rule => {
    const criteria = prettyCriteria(rule.criteria, rule.manufacturer_names).map(line => `<span class="criteria-line">${watchEscape(line)}</span>`).join('') || '<span class="criteria-line">No criteria</span>';
    return `<tr><td><strong class="watch-rule-name">${watchEscape(rule.label)}</strong><small class="match-mode">${watchEscape(rule.match_mode === 'any' ? 'ANY selected criterion' : 'ALL selected criteria')}</small><div class="criteria-list">${criteria}</div></td>
      <td><span class="coverage-label coverage-${watchEscape(rule.filter_coverage)}">${coverageLabel(rule.filter_coverage, rule.enabled)}</span></td>
      <td><label class="rule-toggle"><input type="checkbox" data-action="enabled" data-id="${watchEscape(rule.id)}" ${rule.enabled ? 'checked' : ''}><span>${rule.enabled ? 'Enabled' : 'Paused'}</span></label></td>
      <td><button class="text-button" type="button" data-action="delete-rule" data-id="${watchEscape(rule.id)}">Remove</button></td></tr>`;
  }).join('');
  document.querySelectorAll('[data-list]').forEach(button => button.addEventListener('click', () => {
    activeList = button.dataset.list;
    renderSelectedList();
  }));
  document.querySelectorAll('[data-action="enabled"]').forEach(input => input.addEventListener('change', () => mutate(`/api/watchlists/rules/${encodeURIComponent(input.dataset.id)}/enabled`, 'POST', {enabled: input.checked})));
  document.querySelectorAll('[data-action="delete-rule"]').forEach(button => button.addEventListener('click', () => {
    if (confirm('Remove this rule? Existing match history will stay in Monitor.')) mutate(`/api/watchlists/rules/${encodeURIComponent(button.dataset.id)}`, 'DELETE');
  }));
}

function renderLists() {
  const empty = document.getElementById('watchlists-empty');
  const layout = document.getElementById('watchlists-layout');
  empty.hidden = savedLists.length > 0;
  layout.hidden = savedLists.length === 0;
  if (!savedLists.length) return;
  if (!savedLists.some(item => item.name === activeList)) activeList = savedLists[0].name;
  renderSelectedList();
}

async function loadWatchLists() {
  try {
    const response = await fetch('/api/watchlists', {credentials: 'same-origin'});
    if (response.status === 401) { location.href = '/login'; return; }
    const data = await response.json();
    if (!response.ok) throw Error(data.error || 'Could not load watch lists.');
    savedLists = data.watchlists || [];
    renderLists();
    document.getElementById('watchlists-error').textContent = '';
  } catch (error) {
    document.getElementById('watchlists-error').textContent = error.message;
  }
}

async function mutate(url, method, body) {
  try {
    const response = await fetch(url, {method, credentials: 'same-origin',
      headers: {'X-CSRF-Token': watchCsrf, ...(body ? {'Content-Type': 'application/json'} : {})},
      ...(body ? {body: JSON.stringify(body)} : {})});
    const result = await response.json();
    if (!response.ok) throw Error(result.error || 'Could not save watch-list change.');
    await loadWatchLists();
  } catch (error) {
    document.getElementById('watchlists-error').textContent = error.message;
  }
}

document.getElementById('rename-watchlist').addEventListener('click', () => {
  const name = prompt('New name for this watch list:', activeList);
  if (name !== null) mutate('/api/watchlists/rename', 'POST', {old_name: activeList, new_name: name});
});
document.getElementById('delete-watchlist').addEventListener('click', () => {
  if (confirm(`Delete “${activeList}” and all its rules? Existing match history will stay in Monitor.`)) mutate('/api/watchlists/delete', 'POST', {name: activeList});
});

loadWatchLists();
