// ── DATA ──────────────────────────────────────────────────────────────────────
const CATEGORIES = [
    { id: 'social', label: 'Social', color: '#534AB7', bg: '#EEEDFE' },
    { id: 'finance', label: 'Finance', color: '#0F6E56', bg: '#E1F5EE' },
    { id: 'work', label: 'Work', color: '#185FA5', bg: '#E6F1FB' },
    { id: 'shopping', label: 'Shopping', color: '#993C1D', bg: '#FAECE7' },
    { id: 'other', label: 'Other', color: '#5F5E5A', bg: '#F1EFE8' },
];
const CAT = {};
CATEGORIES.forEach(c => CAT[c.id] = c);

// ── STATE ─────────────────────────────────────────────────────────────────────
let vault = {};
let notes = [];
let openSites = new Set();
let visiblePw = new Set();
let editingKey = null;
let deletingKey = null;
let deletingType = null;
let modalPassVis = false;
let selectedCat = null;
let activeFilter = 'all';
let pinEnabled = true;
let bioEnabled = false;
let userPin = '1234';
let pinInput = '';
let cpinInput = '';
let setupPinInput = '';
let editingNoteIdx = null;
let theme = 'dark';
let encryptionEnabled = false;
let isFirstTime = false;

// ── STORAGE ───────────────────────────────────────────────────────────────────
// IndexedDB for persistent PIN storage
function openDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open('VaultDB', 1);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains('settings')) {
                db.createObjectStore('settings', { keyPath: 'key' });
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function savePinToDB(pin) {
    try {
        const db = await openDB();
        const tx = db.transaction('settings', 'readwrite');
        tx.objectStore('settings').put({ key: 'userPin', value: pin });
        return new Promise((resolve, reject) => {
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject();
        });
    } catch (e) { }
}

async function loadPinFromDB() {
    try {
        const db = await openDB();
        const tx = db.transaction('settings', 'readonly');
        const store = tx.objectStore('settings');
        return new Promise((resolve) => {
            const req = store.get('userPin');
            req.onsuccess = () => resolve(req.result?.value || null);
            req.onerror = () => resolve(null);
        });
    } catch (e) { return null; }
}

function save() {
    try {
        // save settings/meta always
        const meta = { userPin, pinEnabled, bioEnabled, theme, encryptionEnabled };
        localStorage.setItem('vault_data', JSON.stringify(meta));
        // also save PIN to IndexedDB for better persistence on mobile
        savePinToDB(userPin);

        if (encryptionEnabled) {
            // async encrypt and store vault+notes
            (async () => {
                try {
                    let salt = localStorage.getItem('enc_salt');
                    if (!salt) { salt = bytesToBase64(randomBytes(16)); localStorage.setItem('enc_salt', salt); }
                    const key = await deriveKey(userPin, salt);
                    const enc = await encryptPayload({ vault, notes }, key);
                    localStorage.setItem('vault_secure', JSON.stringify({ salt, iv: enc.iv, data: enc.data }));
                    // remove plaintext backup if any
                    localStorage.removeItem('vault_plain');
                } catch (e) { }
            })();
        } else {
            // store plaintext for backwards compatibility
            try { localStorage.setItem('vault_plain', JSON.stringify({ vault, notes })); } catch (e) { }
            localStorage.removeItem('vault_secure');
        }
    } catch (e) { }
}

function load() {
    try {
        const d = JSON.parse(localStorage.getItem('vault_data') || '{}');
        if (d.userPin) userPin = d.userPin;
        if (typeof d.pinEnabled !== 'undefined') pinEnabled = d.pinEnabled;
        if (typeof d.bioEnabled !== 'undefined') bioEnabled = d.bioEnabled;
        if (d.theme) theme = d.theme;
        if (typeof d.encryptionEnabled !== 'undefined') encryptionEnabled = d.encryptionEnabled;

        // load plaintext fallback immediately (will be overwritten if encrypted payload exists)
        const plain = JSON.parse(localStorage.getItem('vault_plain') || 'null');
        if (plain && plain.vault) { vault = plain.vault; }
        if (plain && plain.notes) { notes = plain.notes; }
    } catch (e) { }
}

async function decryptIfNeeded() {
    if (!encryptionEnabled) return;
    try {
        const sec = JSON.parse(localStorage.getItem('vault_secure') || 'null');
        if (!sec || !sec.data) return;
        const key = await deriveKey(userPin, sec.salt);
        const data = await decryptPayload({ iv: sec.iv, data: sec.data }, key);
        if (data && typeof data === 'object') {
            if (data.vault) vault = data.vault;
            if (data.notes) notes = data.notes;
        }
    } catch (err) {
        // decryption failed (likely wrong PIN) — keep vault empty to avoid leaks
        vault = {};
        notes = [];
        showToast('Failed to decrypt data — check PIN');
    }
}

function applyTheme() {
    if (theme === 'light') document.body.classList.add('theme-light');
    else document.body.classList.remove('theme-light');
    const tbtn = document.getElementById('toggle-theme');
    if (tbtn) tbtn.classList.toggle('on', theme === 'light');
}

// Update encrypt toggle UI to match state
function applyEncryptToggle() {
    const btn = document.getElementById('toggle-encrypt');
    if (!btn) return;
    btn.classList.toggle('on', encryptionEnabled);
}

// --- Crypto helpers ---
function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToBytes(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function randomBytes(len) { const b = new Uint8Array(len); crypto.getRandomValues(b); return b; }

async function deriveKey(pin, saltB64) {
    const enc = new TextEncoder().encode(pin);
    const salt = base64ToBytes(saltB64);
    const baseKey = await crypto.subtle.importKey('raw', enc, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptPayload(obj, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(JSON.stringify(obj));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return { iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(ct)) };
}

async function decryptPayload(encObj, key) {
    const iv = base64ToBytes(encObj.iv);
    const ct = base64ToBytes(encObj.data);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return JSON.parse(new TextDecoder().decode(pt));
}

// Toggle encryption on/off (wired to settings toggle)
async function toggleEncrypt() {
    encryptionEnabled = !encryptionEnabled;
    applyEncryptToggle();
    try {
        if (encryptionEnabled) {
            // enable: create salt, derive key and encrypt current vault
            let salt = localStorage.getItem('enc_salt');
            if (!salt) { salt = bytesToBase64(randomBytes(16)); localStorage.setItem('enc_salt', salt); }
            const key = await deriveKey(userPin, salt);
            const enc = await encryptPayload({ vault, notes }, key);
            localStorage.setItem('vault_secure', JSON.stringify({ salt, iv: enc.iv, data: enc.data }));
            // remove plaintext storage for safety
            localStorage.removeItem('vault_plain');
            showToast('Encryption enabled');
        } else {
            // disable: decrypt stored secure (if any) and persist plaintext
            const secRaw = localStorage.getItem('vault_secure');
            if (secRaw) {
                const sec = JSON.parse(secRaw);
                const key = await deriveKey(userPin, sec.salt);
                const data = await decryptPayload({ iv: sec.iv, data: sec.data }, key);
                if (data && typeof data === 'object') { vault = data.vault || {}; notes = data.notes || []; }
            }
            try { localStorage.setItem('vault_plain', JSON.stringify({ vault, notes })); } catch (e) { }
            localStorage.removeItem('vault_secure');
            localStorage.removeItem('enc_salt');
            showToast('Encryption disabled');
        }
    } catch (err) {
        showToast('Encryption error');
        // revert state on failure
        encryptionEnabled = !encryptionEnabled;
        applyEncryptToggle();
    }
    save();
}

function toggleTheme() {
    theme = theme === 'light' ? 'dark' : 'light';
    applyTheme();
    save();
    showToast(theme === 'dark' ? 'Dark theme enabled' : 'Light theme enabled');
}

// ── CLOCK ─────────────────────────────────────────────────────────────────────
function updateClock() {
    const now = new Date();
    const t = now.getHours().toString().padStart(2, '0') + ':' + now.getMinutes().toString().padStart(2, '0');
    ['pin-clock', 'main-clock'].forEach(id => { const el = document.getElementById(id); if (el) el.textContent = t; });
}
setInterval(updateClock, 30000);
updateClock();

// ── TOAST ─────────────────────────────────────────────────────────────────────
function showToast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg; t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2200);
}

// ── NAVIGATION ────────────────────────────────────────────────────────────────
function showTab(tab) {
    ['vault', 'notes', 'settings'].forEach(t => {
        document.getElementById('tab-' + t).style.display = t === tab ? 'flex' : 'none';
        const n = document.getElementById('nav-' + t);
        if (n) n.classList.toggle('active', t === tab);
    });
    if (tab === 'notes') renderNotes();
    if (tab === 'vault') renderVault();
}

// ── PIN ───────────────────────────────────────────────────────────────────────
function pinPress(n) {
    if (pinInput.length >= 4) return;
    pinInput += n; updateDots('pin-dots', 'd', pinInput);
    if (pinInput.length === 4) {
        setTimeout(() => {
            if (pinInput === userPin) {
                document.getElementById('screen-pin').classList.remove('active');
                document.getElementById('screen-main').classList.add('active');
                renderVault();
            } else {
                document.getElementById('pin-error').textContent = 'Incorrect PIN. Try again.';
                pinInput = ''; updateDots('pin-dots', 'd', pinInput);
            }
        }, 120);
    }
}
function pinBack() { pinInput = pinInput.slice(0, -1); document.getElementById('pin-error').textContent = ''; updateDots('pin-dots', 'd', pinInput); }
function updateDots(containerId, prefix, val) {
    for (let i = 0; i < 4; i++) { const el = document.getElementById(prefix + i); if (el) el.classList.toggle('filled', i < val.length); }
}
function cpinPress(n) {
    if (cpinInput.length >= 4) return;
    cpinInput += n; updateDots('chpin-dots', 'cd', cpinInput);
    if (cpinInput.length === 4) {
        setTimeout(() => {
            userPin = cpinInput; cpinInput = '';
            updateDots('chpin-dots', 'cd', cpinInput);
            closeModal('modal-changepin'); save(); showToast('PIN updated');
        }, 120);
    }
}
function cpinBack() { cpinInput = cpinInput.slice(0, -1); updateDots('chpin-dots', 'cd', cpinInput); }
function openChangePin() { cpinInput = ''; updateDots('chpin-dots', 'cd', cpinInput); document.getElementById('modal-changepin').classList.remove('hidden'); }
function togglePinSetting() {
    pinEnabled = !pinEnabled;
    document.getElementById('toggle-pin').classList.toggle('on', pinEnabled);
    save(); showToast(pinEnabled ? 'PIN lock enabled' : 'PIN lock disabled');
}
function toggleBio() {
    bioEnabled = !bioEnabled;
    document.getElementById('toggle-bio').classList.toggle('on', bioEnabled);
    save(); showToast(bioEnabled ? 'Biometric enabled' : 'Biometric disabled');
}

// ── VAULT RENDER ──────────────────────────────────────────────────────────────
function siteIcon(name) { return (name || '?')[0].toUpperCase(); }

function renderStats() {
    const sites = Object.keys(vault).length;
    const accounts = Object.values(vault).reduce((a, b) => a + b.length, 0);
    const sr = document.getElementById('stats-row');
    if (!sr) return;
    sr.innerHTML = sites === 0 ? '' : `
    <div class="stat-card"><div class="stat-num">${sites}</div><div class="stat-lbl">Sites</div></div>
    <div class="stat-card"><div class="stat-num">${accounts}</div><div class="stat-lbl">Accounts</div></div>
    <div class="stat-card"><div class="stat-num">${notes.length}</div><div class="stat-lbl">Notes</div></div>`;
}
function renderFilters() {
    const fr = document.getElementById('filter-row'); if (!fr) return;
    const counts = { all: Object.keys(vault).length };
    CATEGORIES.forEach(c => { counts[c.id] = Object.values(vault).filter(a => a.some(x => x.cat === c.id)).length; });
    fr.innerHTML = `<button class="filter-chip ${activeFilter === 'all' ? 'active' : ''}" onclick="setFilter('all')">All (${counts.all})</button>`
        + CATEGORIES.map(c => counts[c.id] > 0 ? `<button class="filter-chip ${activeFilter === c.id ? 'active' : ''}" onclick="setFilter('${c.id}')">${c.label} (${counts[c.id]})</button>` : '').join('');
}
function setFilter(f) { activeFilter = f; renderVault(); }

function renderVault() {
    renderStats(); renderFilters();
    const q = (document.getElementById('searchInput') || {}).value || '';
    let keys = Object.keys(vault);
    if (q) keys = keys.filter(k => k.toLowerCase().includes(q.toLowerCase()));
    if (activeFilter !== 'all') keys = keys.filter(k => vault[k].some(a => a.cat === activeFilter));
    const list = document.getElementById('vault-list'); if (!list) return;
    if (keys.length === 0) {
        list.innerHTML = `<div class="empty-state"><div class="empty-icon"><i class="ti ti-shield-lock"></i></div><div class="empty-title">${q ? 'No results' : 'No passwords yet'}</div><div class="empty-sub">${q ? 'Try different keywords' : 'Tap + to add your first site'}</div></div>`;
        return;
    }
    list.innerHTML = keys.sort().map(site => {
        const accounts = vault[site];
        const isOpen = openSites.has(site);
        const toShow = activeFilter === 'all' ? accounts : accounts.filter(a => a.cat === activeFilter);
        const mainCat = toShow.find(a => a.cat) ? CAT[toShow.find(a => a.cat).cat] : null;
        const iconBg = mainCat ? mainCat.bg : '#EEEDFE';
        const iconColor = mainCat ? mainCat.color : 'var(--ac)';
        const rows = toShow.map(acc => {
            const i = accounts.indexOf(acc);
            const key = `${site}__${i}`;
            const isVis = visiblePw.has(key);
            const cat = acc.cat ? CAT[acc.cat] : null;
            return `<div class="account-row">
        <div class="account-avatar"><i class="ti ti-user" style="font-size:14px"></i></div>
        <div class="account-details">
          <div class="account-user">${esc(acc.username)}${cat ? `<span class="tag-pill" style="background:${cat.bg};color:${cat.color}">${cat.label}</span>` : ''}</div>
          <div class="account-pass ${isVis ? 'vis' : ''}">${isVis ? esc(acc.password) : '••••••••'}</div>
        </div>
        <div class="row-actions">
          <button class="btn-sm" onclick="togglePw('${esc(site)}',${i})"><i class="ti ti-${isVis ? 'eye-off' : 'eye'}"></i></button>
          <button class="btn-sm" onclick="copyPw('${esc(site)}',${i})"><i class="ti ti-copy"></i></button>
          <button class="btn-sm" onclick="editEntry('${esc(site)}',${i})"><i class="ti ti-edit"></i></button>
          <button class="btn-sm danger" onclick="deleteEntry('${esc(site)}',${i})"><i class="ti ti-trash"></i></button>
        </div>
      </div>`;
        }).join('');
        return `<div class="card">
      <div class="site-header" onclick="toggleSite('${esc(site)}')">
        <div class="site-icon" style="background:${iconBg};color:${iconColor}">${siteIcon(site)}</div>
        <div style="flex:1">
          <div class="site-name">${esc(site)}</div>
          <div class="site-meta">${toShow.length} account${toShow.length !== 1 ? 's' : ''}</div>
        </div>
        <button class="btn-sm" onclick="event.stopPropagation();addToSite('${esc(site)}')" style="margin-right:6px"><i class="ti ti-user-plus"></i></button>
        <i class="ti ti-chevron-right chevron ${isOpen ? 'open' : ''}"></i>
      </div>
      ${isOpen ? `<div class="accounts-list">${rows}</div>` : ''}
    </div>`;
    }).join('');
}

function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }
function toggleSite(s) { openSites.has(s) ? openSites.delete(s) : openSites.add(s); renderVault(); }
function togglePw(s, i) { const k = `${s}__${i}`; visiblePw.has(k) ? visiblePw.delete(k) : visiblePw.add(k); renderVault(); }
function copyPw(s, i) { navigator.clipboard?.writeText(vault[s][i].password).catch(() => { }); showToast('Password copied'); }

// ── ENTRY MODAL ───────────────────────────────────────────────────────────────
function buildCatSel(sel) {
    selectedCat = sel || null;
    const el = document.getElementById('cat-selector'); if (!el) return;
    el.innerHTML = CATEGORIES.map(c => `<button class="cat-chip ${selectedCat === c.id ? 'selected' : ''}" onclick="selectCat('${c.id}')">${c.label}</button>`).join('');
}
function selectCat(id) { selectedCat = id; buildCatSel(id); }

function openAddSite() {
    editingKey = null;
    ['inp-site', 'inp-user', 'inp-pass'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('inp-site').disabled = false;
    document.getElementById('modal-entry-title').textContent = 'Add site';
    buildCatSel(null); updateStrength();
    document.getElementById('modal-entry').classList.remove('hidden');
    setTimeout(() => document.getElementById('inp-site').focus(), 100);
}
function addToSite(site) {
    editingKey = null;
    document.getElementById('inp-site').value = site;
    document.getElementById('inp-site').disabled = true;
    document.getElementById('inp-user').value = '';
    document.getElementById('inp-pass').value = '';
    document.getElementById('modal-entry-title').textContent = `Add account — ${site}`;
    buildCatSel(null); updateStrength();
    document.getElementById('modal-entry').classList.remove('hidden');
    setTimeout(() => document.getElementById('inp-user').focus(), 100);
}
function editEntry(site, i) {
    editingKey = { site, i };
    document.getElementById('inp-site').value = site;
    document.getElementById('inp-site').disabled = true;
    document.getElementById('inp-user').value = vault[site][i].username;
    document.getElementById('inp-pass').value = vault[site][i].password;
    document.getElementById('modal-entry-title').textContent = 'Edit account';
    buildCatSel(vault[site][i].cat || null); updateStrength();
    document.getElementById('modal-entry').classList.remove('hidden');
}
function saveEntry() {
    const site = document.getElementById('inp-site').value.trim();
    const user = document.getElementById('inp-user').value.trim();
    const pass = document.getElementById('inp-pass').value;
    if (!site || !user || !pass) { showToast('All fields required'); return; }
    if (editingKey) {
        vault[editingKey.site][editingKey.i] = { username: user, password: pass, cat: selectedCat };
        showToast('Updated');
    } else {
        if (!vault[site]) vault[site] = [];
        vault[site].push({ username: user, password: pass, cat: selectedCat });
        openSites.add(site);
        showToast('Saved');
    }
    closeModal('modal-entry'); save(); renderVault();
}

// ── STRENGTH ──────────────────────────────────────────────────────────────────
function updateStrength() {
    const pass = document.getElementById('inp-pass').value;
    const bar = document.getElementById('str-bar'); const lbl = document.getElementById('str-label');
    if (!bar || !lbl) return;
    if (!pass) { bar.style.width = '0'; lbl.textContent = 'Enter a password'; lbl.style.color = 'var(--text3)'; return; }
    let sc = 0;
    if (pass.length >= 8) sc++; if (pass.length >= 12) sc++;
    if (/[A-Z]/.test(pass)) sc++; if (/[0-9]/.test(pass)) sc++; if (/[^A-Za-z0-9]/.test(pass)) sc++;
    const lv = [{ w: '18%', c: '#E24B4A', t: 'Very weak' }, { w: '34%', c: '#EF9F27', t: 'Weak' }, { w: '54%', c: '#EF9F27', t: 'Fair' }, { w: '76%', c: '#1D9E75', t: 'Strong' }, { w: '100%', c: '#0F6E56', t: 'Very strong' }];
    const l = lv[Math.min(sc, 4)];
    bar.style.width = l.w; bar.style.background = l.c; lbl.textContent = l.t; lbl.style.color = l.c;
}

function toggleModalPass() {
    modalPassVis = !modalPassVis;
    const inp = document.getElementById('inp-pass'); const btn = document.getElementById('modal-pass-btn');
    inp.type = modalPassVis ? 'text' : 'password';
    btn.innerHTML = `<i class="ti ti-${modalPassVis ? 'eye-off' : 'eye'}"></i>`;
}

// ── DELETE ────────────────────────────────────────────────────────────────────
function deleteEntry(site, i) {
    deletingKey = { site, i }; deletingType = 'entry';
    document.getElementById('confirm-title').textContent = 'Remove this account?';
    document.getElementById('confirm-sub').textContent = 'This will permanently delete the saved credentials.';
    document.getElementById('modal-confirm').classList.remove('hidden');
}
function deleteNote(i) {
    deletingKey = i; deletingType = 'note';
    document.getElementById('confirm-title').textContent = 'Remove this note?';
    document.getElementById('confirm-sub').textContent = 'This will permanently delete the note.';
    document.getElementById('modal-confirm').classList.remove('hidden');
}
function confirmDelete() {
    if (deletingType === 'entry') {
        const { site, i } = deletingKey;
        vault[site].splice(i, 1);
        if (vault[site].length === 0) { delete vault[site]; openSites.delete(site); }
        showToast('Removed'); renderVault();
    } else if (deletingType === 'note') {
        notes.splice(deletingKey, 1); showToast('Note removed'); renderNotes(); renderStats();
    }
    deletingKey = null; save(); closeModal('modal-confirm');
}

// ── NOTES ─────────────────────────────────────────────────────────────────────
function renderNotes() {
    const list = document.getElementById('notes-list'); if (!list) return;
    if (notes.length === 0) {
        list.innerHTML = `<div class="empty-state"><div class="empty-icon"><i class="ti ti-notes"></i></div><div class="empty-title">No notes yet</div><div class="empty-sub">Tap + to write your first note</div></div>`;
        return;
    }
    list.innerHTML = notes.map((n, i) => `<div class="note-card" onclick="openEditNote(${i})">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
      <div class="note-title">${esc(n.title || 'Untitled')}</div>
      <button class="btn-sm danger" onclick="event.stopPropagation();deleteNote(${i})" style="flex-shrink:0"><i class="ti ti-trash"></i></button>
    </div>
    <div class="note-preview">${esc(n.body || 'No content')}</div>
    <div class="note-date">${n.date}</div>
  </div>`).join('');
}
function openAddNote() {
    editingNoteIdx = null;
    document.getElementById('inp-note-title').value = '';
    document.getElementById('inp-note-body').value = '';
    document.getElementById('modal-note-title').textContent = 'New note';
    document.getElementById('modal-note').classList.remove('hidden');
    setTimeout(() => document.getElementById('inp-note-title').focus(), 100);
}
function openEditNote(i) {
    editingNoteIdx = i;
    document.getElementById('inp-note-title').value = notes[i].title;
    document.getElementById('inp-note-body').value = notes[i].body;
    document.getElementById('modal-note-title').textContent = 'Edit note';
    document.getElementById('modal-note').classList.remove('hidden');
}
function saveNote() {
    const title = document.getElementById('inp-note-title').value.trim();
    const body = document.getElementById('inp-note-body').value.trim();
    if (!title && !body) { showToast('Note is empty'); return; }
    const now = new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
    if (editingNoteIdx !== null) { notes[editingNoteIdx] = { title, body, date: now }; showToast('Note updated'); }
    else { notes.push({ title, body, date: now }); showToast('Note saved'); }
    closeModal('modal-note'); save(); renderNotes(); renderStats();
}

// ── EXPORT / IMPORT ───────────────────────────────────────────────────────────
function exportData() {
    try {
        if (encryptionEnabled) {
            // export encrypted payload if available
            const sec = localStorage.getItem('vault_secure');
            if (!sec) { showToast('No encrypted data to export'); return; }
            const blob = new Blob([sec], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = 'vault-backup.vlt'; a.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
            showToast('Encrypted backup exported');
            return;
        }
        const data = { vault, notes, exportedAt: new Date().toISOString(), version: '2.0' };
        const json = JSON.stringify(data);
        const encoded = encodeBase64(json);
        const blob = new Blob([encoded], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'vault-backup.vlt'; a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        showToast('Backup exported');
    } catch (err) { showToast('Export failed'); }
}
function importData(e) {
    const file = e.target.files[0]; if (!file) return;
    // basic size and type checks
    if (file.size > 2 * 1024 * 1024) { showToast('File too large'); e.target.value = ''; return; }
    const reader = new FileReader();
    reader.onload = ev => {
        try {
            const txt = String(ev.target.result || '');
            // try to parse JSON first (encrypted export is JSON)
            try {
                const parsed = JSON.parse(txt);
                if (parsed && parsed.data && parsed.iv && parsed.salt) {
                    // encrypted backup
                    localStorage.setItem('vault_secure', JSON.stringify(parsed));
                    localStorage.setItem('enc_salt', parsed.salt);
                    encryptionEnabled = true;
                    save();
                    decryptIfNeeded().then(() => { renderVault(); renderNotes(); showToast('Encrypted backup restored'); }).catch(() => showToast('Failed to restore encrypted backup'));
                    return;
                }
            } catch (jsonErr) {
                // not JSON, try legacy base64 encoded plaintext
            }

            const decoded = decodeBase64(txt);
            const data = JSON.parse(decoded);
            if (data && typeof data === 'object') {
                if (data.vault) vault = data.vault;
                if (data.notes) notes = data.notes;
                save(); renderVault(); renderNotes();
                showToast('Backup restored');
            } else showToast('Invalid backup file');
        } catch (err) { showToast('Invalid backup file'); }
    };
    reader.readAsText(file);
    e.target.value = '';
}

// UTF-8 safe base64 helpers
function encodeBase64(str) {
    const bytes = new TextEncoder().encode(str);
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary);
}

function decodeBase64(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
}

// ── MODAL CLOSE ───────────────────────────────────────────────────────────────
function closeModal(id) {
    document.getElementById(id).classList.add('hidden');
    if (id === 'modal-entry') {
        modalPassVis = false;
        const p = document.getElementById('inp-pass'); if (p) p.type = 'password';
        const b = document.getElementById('modal-pass-btn'); if (b) b.innerHTML = '<i class="ti ti-eye"></i>';
    }
}

// ── SETUP PIN (FIRST TIME) ─────────────────────────────────────────────────────
function setupPinPress(n) {
    if (setupPinInput.length >= 4) return;
    setupPinInput += n; updateDots('setup-pins', 'setup-d', setupPinInput);
    if (setupPinInput.length === 4) {
        setTimeout(() => {
            userPin = setupPinInput;
            setupPinInput = '';
            save();
            document.getElementById('screen-setup').classList.remove('active');
            document.getElementById('screen-main').classList.add('active');
            renderVault();
            showToast('PIN set successfully');
        }, 120);
    }
}

function setupPinBack() {
    setupPinInput = setupPinInput.slice(0, -1);
    updateDots('setup-pins', 'setup-d', setupPinInput);
}

// ── BOOT ──────────────────────────────────────────────────────────────────────
async function initializeApp() {
    load();
    applyTheme();
    applyEncryptToggle();
    
    // Check if this is the first time - no PIN set and no vault data
    if (userPin === '1234' && Object.keys(vault).length === 0) {
        isFirstTime = true;
    } else if (!userPin || userPin === '1234') {
        // Try to recover PIN from IndexedDB
        const pinFromDB = await loadPinFromDB();
        if (pinFromDB) {
            userPin = pinFromDB;
            isFirstTime = false;
        } else if (userPin === '1234' && Object.keys(vault).length === 0) {
            isFirstTime = true;
        }
    }
}

// Start the app initialization
const initPromise = initializeApp();
const decryptPromise = decryptIfNeeded();

function bootContinue() {
    try {
        document.getElementById('splash').classList.add('hide');
        setTimeout(() => {
            document.getElementById('splash').style.display = 'none';
            if (isFirstTime) {
                document.getElementById('screen-setup').classList.add('active');
            } else if (pinEnabled) {
                document.getElementById('screen-pin').classList.add('active');
            } else {
                document.getElementById('screen-main').classList.add('active');
                renderVault();
            }
        }, 400);
    } catch (e) { }
}

// Continue boot after initialization and a short delay
initPromise.then(() => {
    setTimeout(bootContinue, 1800);
});

// When decryption finishes, update UI if needed.
decryptPromise.then(() => {
    // If main screen already visible, refresh content to show decrypted data.
    const mainVisible = document.getElementById('screen-main').classList.contains('active');
    if (mainVisible) renderVault();
}).catch(() => {
    // If decryption fails, show a non-blocking message and still continue.
    showToast('Failed to decrypt data — check PIN');
});

// Register service worker for PWA (silent fail if unsupported)
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/service-worker.js').catch(() => { });
}
