const text = (id, value) => {
  const element = document.getElementById(id);
  if (element) element.textContent = value ?? '—';
};

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? 'Time unavailable' : date.toLocaleString();
}

function renderMatches(events) {
  const target = document.getElementById('events');
  if (!events.length) {
    target.innerHTML = '<p class="empty-state">No signature matches recorded yet.</p>';
    return;
  }
  target.innerHTML = events.map(event => `
    <div class="record-row">
      <div><strong class="record-title">${escapeHtml(event.signature_name || 'Unnamed signature')}${event.protocol ? ` · ${escapeHtml(event.protocol.toUpperCase())}` : ''}</strong>
      <small class="record-detail">${event.effective_score !== null && event.effective_score !== undefined
        ? `Score ${Number(event.effective_score)} (${Number(event.base_score) || 0}${Number(event.correlation_bonus) ? ` + ${Number(event.correlation_bonus)} correlation` : ''}) · Indicator match, not confirmation`
        : `${escapeHtml(event.confidence || 'Unclassified')} confidence${event.watchlist_name ? ` · ${escapeHtml(event.watchlist_name)}` : ''}`}
        · ${escapeHtml(formatTime(event.last_seen))}${event.source_note ? `<br>${escapeHtml(event.source_note)}` : ''}</small></div>
      <span class="record-count">${event.protocol ? escapeHtml(event.observed_ssid || event.observed_name || event.observed_identifier || '') : `${Number(event.observation_count) || 0} obs.`}</span>
    </div>`).join('');
}

async function loadMonitor() {
  try {
    const responses = await Promise.all(['/api/status', '/api/events'].map(url => fetch(url, { credentials: 'same-origin' })));
    if (responses[0].status === 401) { location.href = '/login'; return; }
    if (responses.some(response => !response.ok)) throw Error('Could not read the Pi status. Try refreshing.');
    const [status, eventData] = await Promise.all(responses.map(response => response.json()));
    const state = document.getElementById('state');
    state.className = 'state-tag ready';
    state.innerHTML = '<i></i>Pi reachable';
    const scanner = status.scanner || 'unknown';
    text('scanner', scanner === 'active' ? 'Running' : scanner === 'inactive' ? 'Stopped' : scanner);
    text('mode', status.scan_mode || '—');
    text('scan-kicker', `LIVE MONITOR · ${String(status.effective_scan_mode || status.scan_mode || 'SCAN').toUpperCase()} SCAN`);
    text('count', (eventData.events || []).length);
    text('ap', status.wifi_mode === 'scan' ? 'Scanning' : status.access_point ? 'Hotspot' : 'Off');
    text('updated', `Updated ${new Date().toLocaleTimeString()}`);
    renderMatches(eventData.events || []);
    text('error', '');
  } catch (error) {
    const state = document.getElementById('state');
    state.className = 'state-tag error';
    state.innerHTML = '<i></i>Pi unreachable';
    text('error', error.message);
  }
}

document.getElementById('refresh')?.addEventListener('click', loadMonitor);
loadMonitor();
setInterval(loadMonitor, 5000);
