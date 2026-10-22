const token = document.querySelector('meta[name="csrf-token"]').content;
const msg = document.getElementById('message');
const available = document.getElementById('available');
const staged = document.getElementById('staged');
const progressPanel = document.getElementById('apply-progress');
let applyInProgress = false;
let installedVersion = '';
let downloadAvailable = false;

async function request(url, {method = 'GET', body, headers = {}} = {}) {
  const response = await fetch(url, {method, headers: {'X-CSRF-Token': token, ...headers}, body, cache: 'no-store'});
  const data = await response.json();
  if (!response.ok) throw Error(data.error || 'Request failed');
  return data;
}

function showProgress(title, detail, version = '') {
  document.getElementById('apply-progress-title').textContent = title;
  document.getElementById('apply-progress-detail').textContent = detail;
  document.getElementById('apply-progress-version').textContent = version ? `Target ${version}` : '';
  progressPanel.hidden = false;
}

function setBusy(busy) {
  applyInProgress = busy;
  document.body.classList.toggle('updates-busy', busy);
  document.querySelectorAll('#check, #upload input, #upload button')
    .forEach(control => { control.disabled = busy; });
  document.getElementById('stage-download').disabled = busy || !downloadAvailable;
  document.querySelectorAll('[data-apply-button]')
    .forEach(button => { button.disabled = busy || button.dataset.installed === 'true'; });
}

async function refresh() {
  try {
    const data = await request('/api/updates/status');
    installedVersion = data.installed_version;
    document.getElementById('installed').textContent = `Installed version ${installedVersion}`;
    document.getElementById('last-check').textContent = data.last_check;
    staged.replaceChildren();
    if (!data.staged?.length) {
      const empty = document.createElement('p');
      empty.className = 'empty';
      empty.textContent = 'No staged builds.';
      staged.append(empty);
      return;
    }
    for (const build of data.staged) {
      const row = document.createElement('div');
      row.className = 'row';
      const title = document.createElement('strong');
      title.textContent = `Version ${build.version} · ${build.source}`;
      const button = document.createElement('button');
      button.type = 'button';
      button.dataset.applyButton = '';
      button.dataset.installed = String(build.version === installedVersion);
      button.textContent = build.version === installedVersion ? 'Installed' : 'Apply';
      button.disabled = applyInProgress || build.version === installedVersion;
      button.addEventListener('click', () => applyBuild(build));
      row.append(title, button);
      staged.append(row);
    }
  } catch (error) {
    if (!applyInProgress) msg.textContent = error.message;
  }
}

const delay = milliseconds => new Promise(resolve => window.setTimeout(resolve, milliseconds));

async function waitForInstalledVersion(targetVersion, previousVersion) {
  const deadline = Date.now() + 6 * 60 * 1000;
  let connectionDropped = false;
  let previousVersionChecks = 0;
  while (Date.now() < deadline) {
    try {
      const response = await fetch('/api/updates/status', {credentials: 'same-origin', cache: 'no-store'});
      if (response.status === 401) {
        location.href = '/login';
        throw Error('Sign in again to check the update.');
      }
      if (!response.ok) throw Error('Pi is restarting');
      const status = await response.json();
      installedVersion = status.installed_version;
      document.getElementById('installed').textContent = `Installed version ${installedVersion}`;
      if (installedVersion === targetVersion) {
        showProgress('Update complete', `BLE’s Clues is back online on version ${targetVersion}.`, targetVersion);
        setBusy(false);
        await refresh();
        window.setTimeout(() => { progressPanel.hidden = true; }, 12000);
        return true;
      }
      if (installedVersion === previousVersion) previousVersionChecks += 1;
      else previousVersionChecks = 0;
      if (previousVersionChecks >= 6) {
        showProgress('Update rolled back', `The Pi is back online on ${previousVersion}. Its health check likely restored the previous version.`, targetVersion);
        setBusy(false);
        await refresh();
        return false;
      }
      showProgress('Applying update', connectionDropped
        ? 'Pi is reachable; waiting for the restart and checking the installed version.'
        : 'Waiting for the Pi to restart and report the installed version.', targetVersion);
    } catch (error) {
      if (error.message === 'Sign in again to check the update.') throw error;
      connectionDropped = true;
      previousVersionChecks = 0;
      showProgress('Pi is restarting', 'Pi is restarting — reconnecting automatically. Do not apply again while it restarts.', targetVersion);
    }
    await delay(2000);
  }
  showProgress('Update status not confirmed', 'The Pi has not confirmed the target version yet. Check its status before trying Apply again.', targetVersion);
  setBusy(false);
  return false;
}

async function applyBuild(build) {
  if (applyInProgress || build.version === installedVersion) return;
  if (!window.confirm(`Apply version ${build.version}? The app will restart. Keep this page open while it reconnects.`)) return;
  setBusy(true);
  showProgress('Applying update', `Applying version ${build.version}. Do not apply again while the Pi is restarting. Keep this page open.`, build.version);
  msg.textContent = '';
  try {
    const result = await request('/api/updates/apply', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id: build.id, confirm: true})
    });
    if (result.success !== true) throw Error(result.message || 'The update could not be applied.');
    showProgress('Restarting to finish update', result.message || 'Update applied. Waiting for the Pi to reconnect.', build.version);
  } catch (error) {
    // The web service may drop this request while it restarts. Confirm state by
    // reconnecting instead of asking the operator to submit the update again.
    if (error instanceof TypeError || error instanceof SyntaxError) {
      showProgress('Pi is restarting', 'Pi is restarting — reconnecting automatically. Do not apply again while it restarts.', build.version);
    } else {
      msg.textContent = error.message;
      progressPanel.hidden = true;
      setBusy(false);
      await refresh();
      return;
    }
  }
  try {
    const success = await waitForInstalledVersion(build.version, installedVersion);
    if (!success) msg.textContent = 'Review the update status before trying again.';
  } catch (error) {
    msg.textContent = error.message;
    setBusy(false);
  }
}

document.getElementById('check').addEventListener('click', async () => {
  msg.textContent = 'Checking…';
  try {
    const result = await request('/api/updates/check', {method: 'POST'});
    available.textContent = `Version ${result.version}: ${result.release_notes}`;
    downloadAvailable = true;
    document.getElementById('stage-download').disabled = applyInProgress;
    msg.textContent = 'Signed release verified.';
    await refresh();
  } catch (error) {
    msg.textContent = error.message;
    await refresh();
  }
});

document.getElementById('stage-download').addEventListener('click', async () => {
  try {
    const result = await request('/api/updates/stage', {method: 'POST'});
    msg.textContent = `Version ${result.version} staged.`;
    await refresh();
  } catch (error) { msg.textContent = error.message; }
});

document.getElementById('upload').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const result = await request('/api/updates/upload', {method: 'POST', body: new FormData(form)});
    msg.textContent = `Version ${result.version} signature verified and staged.`;
    form.reset();
    await refresh();
  } catch (error) { msg.textContent = error.message; }
});

refresh();
