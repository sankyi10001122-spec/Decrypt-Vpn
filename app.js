'use strict';

// Config Vault format (CVLT1): magic bytes + 4-byte big-endian JSON header length
// + UTF-8 JSON metadata + AES-256-GCM authenticated ciphertext.
// Header bytes are authenticated as AES-GCM additionalData to prevent metadata edits.
const MAGIC = new Uint8Array([0x43, 0x56, 0x4c, 0x54, 0x31]); // CVLT1
const ITERATIONS = 600000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BITS = 128;
const MAX_FILE_BYTES = 100 * 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

const $ = (id) => document.getElementById(id);
const statusEl = $('status');
let encryptFile = null;
let decryptFile = null;

function showStatus(message, type = 'info') {
  statusEl.textContent = message;
  statusEl.className = `status ${type}`;
}
function clearStatus() { statusEl.textContent = ''; statusEl.className = 'status'; }
function setBusy(button, busy, label) {
  button.disabled = busy;
  if (busy) { button.dataset.old = button.textContent; button.textContent = label; }
  else if (button.dataset.old) { button.textContent = button.dataset.old; delete button.dataset.old; }
}
function setFile(kind, file) {
  if (kind === 'encrypt') { encryptFile = file || null; $('encryptName').textContent = file ? `${file.name} · ${formatBytes(file.size)}` : 'ဖိုင် မရွေးရသေးပါ'; }
  else { decryptFile = file || null; $('decryptName').textContent = file ? `${file.name} · ${formatBytes(file.size)}` : 'ဖိုင် မရွေးရသေးပါ'; }
  clearStatus();
}
function formatBytes(n) { return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`; }
function safeFilename(name) {
  const cleaned = String(name || 'decrypted-file').replace(/[\\/\0-\x1f\x7f]/g, '_').replace(/^\.+/, '').slice(0, 240);
  return cleaned || 'decrypted-file';
}
function download(bytes, name, type = 'application/octet-stream') {
  const blob = new Blob([bytes], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = safeFilename(name);
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 30000);
}
async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
function joinBytes(...parts) { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out; }
function makePrefix(headerBytes) {
  const len = new Uint8Array(4); new DataView(len.buffer).setUint32(0, headerBytes.length, false);
  return joinBytes(MAGIC, len, headerBytes);
}
function equalMagic(bytes) { return MAGIC.every((v, i) => bytes[i] === v); }

async function handleEncrypt() {
  const button = $('encryptButton');
  try {
    if (!encryptFile) throw new Error('ပထမဦးစွာ encrypt လုပ်မည့်ဖိုင်ကို ရွေးပါ။');
    if (encryptFile.size > MAX_FILE_BYTES) throw new Error('ဒီ browser tool အတွက် အများဆုံးဖိုင်အရွယ်အစားမှာ 100 MB ဖြစ်သည်။');
    const password = $('encryptPassword').value;
    if (password.length < 12) throw new Error('စကားဝှက်ကို အနည်းဆုံး 12 လုံးထားပါ။ ပိုရှည်ပြီး ခန့်မှန်းရခက်လေ ပိုကောင်းလေဖြစ်သည်။');
    if (password !== $('encryptConfirm').value) throw new Error('စကားဝှက်နှစ်ခု မတူပါ။');
    if (!crypto?.subtle) throw new Error('Web Crypto မရနိုင်ပါ။ HTTPS သို့မဟုတ် localhost မှ ဖွင့်ပါ။');
    setBusy(button, true, 'Encrypt လုပ်နေသည်…');
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const metadata = { version: 1, cipher: 'AES-256-GCM', kdf: 'PBKDF2-SHA-256', iterations: ITERATIONS, salt: toBase64(salt), iv: toBase64(iv), filename: safeFilename(encryptFile.name), mime: encryptFile.type || 'application/octet-stream', size: encryptFile.size };
    const headerBytes = encoder.encode(JSON.stringify(metadata));
    const prefix = makePrefix(headerBytes);
    const key = await deriveKey(password, salt);
    const plain = await encryptFile.arrayBuffer();
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: prefix, tagLength: TAG_BITS }, key, plain));
    download(joinBytes(prefix, encrypted), `${safeFilename(encryptFile.name)}.enc`);
    $('encryptPassword').value = ''; $('encryptConfirm').value = '';
    showStatus('Encrypt ပြီးပါပြီ။ .enc ဖိုင်ကို သိမ်းဆည်းထားပါ။ စကားဝှက်ကို သီးခြားလုံခြုံသောနည်းလမ်းဖြင့် မျှဝေပါ။', 'success');
  } catch (error) { showStatus(error.message || 'Encrypt မအောင်မြင်ပါ။', 'error'); }
  finally { setBusy(button, false); }
}

async function handleDecrypt() {
  const button = $('decryptButton');
  try {
    if (!decryptFile) throw new Error('ပထမဦးစွာ ဒီ tool ဖြင့် encrypt လုပ်ထားသော .enc ဖိုင်ကို ရွေးပါ။');
    if (decryptFile.size > MAX_FILE_BYTES + 65536) throw new Error('ဒီ browser tool အတွက် အများဆုံးဖိုင်အရွယ်အစားမှာ 100 MB ဖြစ်သည်။');
    const password = $('decryptPassword').value;
    if (!password) throw new Error('စကားဝှက်ကို ထည့်ပါ။');
    if (!crypto?.subtle) throw new Error('Web Crypto မရနိုင်ပါ။ HTTPS သို့မဟုတ် localhost မှ ဖွင့်ပါ။');
    setBusy(button, true, 'Decrypt လုပ်နေသည်…');
    const data = new Uint8Array(await decryptFile.arrayBuffer());
    if (data.length < 9 || !equalMagic(data)) throw new Error('ဒီဖိုင်က Config Vault CVLT1 format မဟုတ်ပါ။ အခြား app ၏ lock ကို ဒီ tool ဖြင့် ဖြည်မရပါ။');
    const headerLength = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(5, false);
    const headerStart = 9, cipherStart = headerStart + headerLength;
    if (headerLength < 2 || headerLength > 8192 || cipherStart >= data.length) throw new Error('ဖိုင် header မမှန်ပါ သို့မဟုတ် ဖိုင်ပျက်နေသည်။');
    const headerBytes = data.slice(headerStart, cipherStart);
    let meta;
    try { meta = JSON.parse(decoder.decode(headerBytes)); } catch { throw new Error('ဖိုင် metadata ကို ဖတ်မရပါ။'); }
    if (meta.version !== 1 || meta.cipher !== 'AES-256-GCM' || meta.kdf !== 'PBKDF2-SHA-256' || meta.iterations !== ITERATIONS) throw new Error('ဒီဖိုင်၏ format/version ကို မပံ့ပိုးပါ။');
    const salt = fromBase64(meta.salt), iv = fromBase64(meta.iv);
    if (salt.length !== SALT_BYTES || iv.length !== IV_BYTES || !Number.isSafeInteger(meta.size) || meta.size < 0 || meta.size > MAX_FILE_BYTES) throw new Error('ဖိုင် metadata မမှန်ပါ သို့မဟုတ် သတ်မှတ်ချက်ကျော်လွန်နေသည်။');
    const prefix = data.slice(0, cipherStart);
    const key = await deriveKey(password, salt);
    let plain;
    try { plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: prefix, tagLength: TAG_BITS }, key, data.slice(cipherStart)); }
    catch { throw new Error('စကားဝှက်မှားနေသည် သို့မဟုတ် ဖိုင်ကို ပြင်ဆင်ထား/ပျက်စီးနေသည်။'); }
    if (plain.byteLength !== meta.size) throw new Error('ဖိုင်အရွယ်အစား စစ်ဆေးမှု မအောင်မြင်ပါ။');
    download(plain, safeFilename(meta.filename), typeof meta.mime === 'string' ? meta.mime : 'application/octet-stream');
    $('decryptPassword').value = '';
    showStatus('Decrypt ပြီးပါပြီ။ မူရင်းဖိုင်ကို download လုပ်ထားပါပြီ။', 'success');
  } catch (error) { showStatus(error.message || 'Decrypt မအောင်မြင်ပါ။', 'error'); }
  finally { setBusy(button, false); }
}
function fromBase64(s) { if (typeof s !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) throw new Error('ဖိုင် metadata ထဲက key data မမှန်ပါ။'); const raw = atob(s); return Uint8Array.from(raw, c => c.charCodeAt(0)); }
function toBase64(bytes) { let s = ''; bytes.forEach(b => { s += String.fromCharCode(b); }); return btoa(s); }

$('encryptFile').addEventListener('change', e => setFile('encrypt', e.target.files[0]));
$('decryptFile').addEventListener('change', e => setFile('decrypt', e.target.files[0]));
$('encryptButton').addEventListener('click', handleEncrypt);
$('decryptButton').addEventListener('click', handleDecrypt);
$('encryptTab').addEventListener('click', () => switchTab('encrypt'));
$('decryptTab').addEventListener('click', () => switchTab('decrypt'));
function switchTab(which) {
  const enc = which === 'encrypt';
  $('encryptPanel').hidden = !enc; $('decryptPanel').hidden = enc;
  $('encryptPanel').classList.toggle('hidden', !enc); $('decryptPanel').classList.toggle('hidden', enc);
  $('encryptTab').classList.toggle('active', enc); $('decryptTab').classList.toggle('active', !enc);
  $('encryptTab').setAttribute('aria-selected', String(enc)); $('decryptTab').setAttribute('aria-selected', String(!enc)); clearStatus();
}
for (const [id, kind] of [['encryptDrop','encrypt'],['decryptDrop','decrypt']]) {
  const zone = $(id);
  for (const event of ['dragenter','dragover']) zone.addEventListener(event, e => { e.preventDefault(); zone.classList.add('drag'); });
  for (const event of ['dragleave','drop']) zone.addEventListener(event, e => { e.preventDefault(); zone.classList.remove('drag'); });
  zone.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) setFile(kind, f); });
}
