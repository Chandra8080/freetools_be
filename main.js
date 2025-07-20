import express from "express";
import path from "path";
import qrcode from "qrcode";
import compression from "compression";
import axios from "axios";
import JavaScriptObfuscator from "javascript-obfuscator";
import figlet from "figlet";
import { promises as dns } from "dns";
import net from "net";
import cors from "cors";
const app = express();

const JSONBIN_URL = "https://api.jsonbin.io/v3/b/684273718960c979a5a5cf1b";
const JSONBIN_MASTER_KEY = "$2a$10$ZOU4Y0227S0w6INCkbD7w.Jfec20GXsau9EK7SLYtlqpGNlA5zyJO";
const JSONBIN_ACCESS_KEY = "$2a$10$DR3we293VRRhhFEokhAYh.6o4n4HNziSAe3Tl8FYSxZJXNK4dtiNS";

const JSONBIN_NOTES_URL = "https://api.jsonbin.io/v3/b/684273508960c979a5a5cf18";
const JSONBIN_NOTES_MASTER_KEY = "$2a$10$ZOU4Y0227S0w6INCkbD7w.Jfec20GXsau9EK7SLYtlqpGNlA5zyJO";
const JSONBIN_NOTES_ACCESS_KEY = "$2a$10$DR3we293VRRhhFEokhAYh.6o4n4HNziSAe3Tl8FYSxZJXNK4dtiNS";

let suggestionsCache = [];
let notesData = { notes: {} };

async function fetchSuggestionsFromBin() {
  try {
    const response = await axios.get(`${JSONBIN_URL}/latest`, {
      headers: {
        'X-Access-Key': JSONBIN_ACCESS_KEY,
        'X-Bin-Meta': false
      },
      timeout: 5000
    });
    let data = response.data;
    if (typeof data === 'object' && data !== null && 'record' in data && Array.isArray(data.record)) {
      data = data.record;
    }
    suggestionsCache = Array.isArray(data) ? data : [];
    return suggestionsCache;
  } catch (error) {
    suggestionsCache = [];
    return [];
  }
}

async function updateSuggestionsInBin(newSuggestions) {
  try {
    await axios.put(JSONBIN_URL, newSuggestions, {
      headers: {
        'Content-Type': 'application/json',
        'X-Master-Key': JSONBIN_MASTER_KEY
      },
      timeout: 5000
    });
    suggestionsCache = newSuggestions;
    return true;
  } catch (error) {
    console.error("Failed to update suggestions in JSONBin:", error.message);
    return false;
  }
}

async function fetchNotesFromBin() {
  try {
    const response = await axios.get(`${JSONBIN_NOTES_URL}/latest`, {
      headers: {
        'X-Access-Key': JSONBIN_NOTES_ACCESS_KEY,
        'X-Bin-Meta': false
      },
      timeout: 5000
    });
    let data = response.data;
    if (typeof data === 'object' && data !== null && 'record' in data && typeof data.record === 'object' && data.record !== null) {
      notesData = data.record;
    } else if (typeof data === 'object' && data !== null && 'notes' in data) {
      notesData = data;
    } else {
      notesData = { notes: {} };
    }
    if (!notesData || typeof notesData.notes !== 'object') {
      notesData = { notes: {} };
    }
    return notesData;
  } catch (error) {
    notesData = { notes: {} };
    return notesData;
  }
}

async function updateNotesInBin(dataToSave) {
  try {
    await axios.put(JSONBIN_NOTES_URL, dataToSave, {
      headers: {
        'Content-Type': 'application/json',
        'X-Master-Key': JSONBIN_NOTES_MASTER_KEY
      },
      timeout: 5000
    });
    notesData = dataToSave;
    return true;
  } catch (error) {
    console.error("Failed to update notes in JSONBin:", error.message);
    return false;
  }
}

(async () => {
  suggestionsCache = await fetchSuggestionsFromBin();
  notesData = await fetchNotesFromBin();
})();

const noteCodeLength = 4;

function generateUniqueNoteCode() {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let code = '';
  for (let i = 0; i < noteCodeLength; i++) {
    code += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  if (notesData.notes && notesData.notes[code]) {
    return generateUniqueNoteCode();
  }
  return code;
}

const rateLimit = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const MAX_REQUESTS = 50;

app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const now = Date.now();

  if (!rateLimit.has(ip)) {
    rateLimit.set(ip, []);
  }
  const timestamps = rateLimit.get(ip);

  while (timestamps.length > 0 && timestamps[0] < now - RATE_LIMIT_WINDOW) {
    timestamps.shift();
  }

  timestamps.push(now);

  if (timestamps.length > MAX_REQUESTS) {
    res.status(429).send('Terlalu Banyak Permintaan');
  } else {
    next();
  }
});

const noteCreateRateLimit = new Map();
const NOTE_CREATE_WINDOW_MS = 10 * 60 * 1000;
const MAX_NOTE_CREATES_PER_WINDOW = 2;

const noteCreateRateLimiter = (req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const now = Date.now();

  if (!noteCreateRateLimit.has(ip)) {
    noteCreateRateLimit.set(ip, []);
  }
  const timestamps = noteCreateRateLimit.get(ip);

  while (timestamps.length > 0 && timestamps[0] < now - NOTE_CREATE_WINDOW_MS) {
    timestamps.shift();
  }

  timestamps.push(now);

  if (timestamps.length > MAX_NOTE_CREATES_PER_WINDOW) {
    return res.status(429).json({ error: 'Anda terlalu sering membuat catatan. Silakan coba lagi nanti.' });
  }
  next();
};

const suggestionSubmitRateLimit = new Map();
const SUGGESTION_SUBMIT_WINDOW_MS = 5 * 60 * 1000;
const MAX_SUGGESTION_SUBMITS_PER_WINDOW = 1;

const suggestionSubmitRateLimiter = (req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const now = Date.now();

  if (!suggestionSubmitRateLimit.has(ip)) {
    suggestionSubmitRateLimit.set(ip, []);
  }
  const timestamps = suggestionSubmitRateLimit.get(ip);

  while (timestamps.length > 0 && timestamps[0] < now - SUGGESTION_SUBMIT_WINDOW_MS) {
    timestamps.shift();
  }

  timestamps.push(now);

  if (timestamps.length > MAX_SUGGESTION_SUBMITS_PER_WINDOW) {
    return res.status(429).json({ error: 'Anda terlalu sering mengirim saran/kritik. Silakan coba lagi nanti.' });
  }
  next();
};

const captchaRequestRateLimit = new Map();
const CAPTCHA_REQUEST_WINDOW_MS = 60 * 1000;
const MAX_CAPTCHA_REQUESTS_PER_WINDOW = 20;

const captchaRequestRateLimiter = (req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const now = Date.now();

  if (!captchaRequestRateLimit.has(ip)) {
    captchaRequestRateLimit.set(ip, []);
  }
  const timestamps = captchaRequestRateLimit.get(ip);

  while (timestamps.length > 0 && timestamps[0] < now - CAPTCHA_REQUEST_WINDOW_MS) {
    timestamps.shift();
  }

  timestamps.push(now);

  if (timestamps.length > MAX_CAPTCHA_REQUESTS_PER_WINDOW) {
    return res.status(429).json({ error: 'Anda terlalu sering meminta captcha. Silakan coba lagi nanti.' });
  }
  next();
};

app.use(compression({ level: 9 }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public'));

const getBaseUrl = (req) => {
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers.host;
  return `${protocol}://${host}`;
};

const getServerHostname = (req) => {
  return req.headers.host ? req.headers.host.split(':')[0] : null;
};

const validateReferer = (req, res, next) => {
  const refererHeader = req.headers.referer;
  const expectedHostname = getServerHostname(req);

  if (!expectedHostname) {
    return res.status(500).json({ error: 'Kesalahan server internal: Tidak dapat menentukan hostname.' });
  }

  if (!refererHeader) {
    return res.status(403).json({ error: 'Akses ditolak: Permintaan harus berasal dari website ini.' });
  }

  try {
    const refererUrl = new URL(refererHeader);
    if (refererUrl.hostname.toLowerCase() !== expectedHostname.toLowerCase()) {
      return res.status(403).json({ error: 'Akses ditolak: Permintaan harus berasal dari website ini.' });
    }
  } catch (e) {
    return res.status(403).json({ error: 'Akses ditolak: Referer tidak valid.' });
  }
  next();
};

const isLocalhostIP = (ip) => ip === '127.0.0.1' || ip === '::1';
const isPrivateIP = (ip) => {
  return /^(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})|(169\.254\.\d{1,3}\.\d{1,3})$/.test(ip);
};

const blockedServerHosts = (req) => {
  const serverHost = getServerHostname(req);
  return ['freetools.web.id', serverHost, 'localhost', '127.0.0.1'].filter(Boolean).map(h => h.toLowerCase());
};

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/qris', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'qris.html'));
});

app.get('/base64', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'base64.html'));
});

app.get('/status-checker', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'status-checker.html'));
});

app.get('/obfuscator', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'obfuscator.html'));
});

app.get('/ascii', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ascii.html'));
});

app.get('/notepad', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'notepad.html'));
});

app.get('/api-testing', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'api_testing.html'));
});

app.get('/dns-lookup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dns-lookup.html'));
});

app.get('/sub-finder', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'subfinder.html'));
});

app.get('/check-port', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'check_port.html'));
});

app.get('/ai', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ai.html'));
});

app.get('/caklontong', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'caklontong.html'));
});

app.get('/imagetoascii', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'imgtoascii.html'));
});

app.get('/siapakahaku', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'siapakahaku.html'));
});

app.get('/yt-downloader', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ytdownload.html'));
});

app.get('/tt-downloader', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'tt-download.html'));
});

app.get('/view-source', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'view-source.html'));
});

app.get('/:code', (req, res) => {
  const code = req.params.code;
  if (notesData.notes[code]) {
    return res.sendFile(path.join(__dirname, 'public', 'notepad.html'));
  }
  res.sendFile(path.join(__dirname, 'public', '404.html'));
});

app.get('/api/suggestions', async (req, res) => {
  const currentSuggestions = await fetchSuggestionsFromBin();
  res.status(200).json(currentSuggestions);
});

const captchas = {};
const CAPTCHA_EXPIRATION_MS = 5 * 60 * 1000;
const CLIENT_VERIFICATION_OFFSET = 12345 * 7;
const CLIENT_VERIFICATION_TOLERANCE_MS = 2000;

function generateUniqueId() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

function generateCaptcha() {
  const type = Math.floor(Math.random() * 3);
  let num1, num2, question, answer;
  const words = ['nol', 'satu', 'dua', 'tiga', 'empat', 'lima', 'enam', 'tujuh', 'delapan', 'sembilan', 'sepuluh', 'sebelas', 'dua belas', 'tiga belas', 'empat belas', 'lima belas'];
  const operators = [{ op: '+', text: 'ditambah' }, { op: '-', text: 'dikurangi' }, { op: '*', text: 'dikali' }];
  const selectedOperator = operators[Math.floor(Math.random() * operators.length)];

  switch (type) {
    case 0:
      num1 = Math.floor(Math.random() * 15) + 1;
      num2 = Math.floor(Math.random() * 10) + 1;
      if (selectedOperator.op === '-') {
        [num1, num2] = [Math.max(num1, num2), Math.min(num1, num2)];
      }
      question = `${num1} ${selectedOperator.op} ${num2}`;
      break;
    case 1:
      num1 = Math.floor(Math.random() * 10);
      num2 = Math.floor(Math.random() * 10);
      if (selectedOperator.op === '-') {
        [num1, num2] = [Math.max(num1, num2), Math.min(num1, num2)];
      }
      question = `${words[num1]} ${selectedOperator.text} ${words[num2]}`;
      break;
    case 2:
      const firstIsWord = Math.random() < 0.5;
      num1 = Math.floor(Math.random() * 10);
      num2 = Math.floor(Math.random() * 10);
      if (selectedOperator.op === '-') {
        [num1, num2] = [Math.max(num1, num2), Math.min(num1, num2)];
      }
      const n1 = firstIsWord ? words[num1] : num1;
      const n2 = firstIsWord ? num2 : words[num2];
      question = `${n1} ${selectedOperator.text} ${n2}`;
      if (Math.random() < 0.3) {
        question = `Coba hitung: ${question} (misalnya)`;
      }
      break;
  }

  switch (selectedOperator.op) {
    case '+': answer = num1 + num2; break;
    case '-': answer = num1 - num2; break;
    case '*': answer = num1 * num2; break;
  }

  return { question, answer: answer.toString() };
}

const MIN_CAPTCHA_SOLVE_TIME_MS = 2000;
const TIME_SKEW_TOLERANCE_MS = 1000;

app.get('/api/captcha', validateReferer, captchaRequestRateLimiter, (req, res) => {
  const { question, answer } = generateCaptcha();

  const captchaId = generateUniqueId();
  const captchaGenerationTimestamp = Date.now();

  captchas[captchaId] = {
    answer: answer,
    timestamp: captchaGenerationTimestamp
  };

  for (const id in captchas) {
    if (Date.now() - captchas[id].timestamp > CAPTCHA_EXPIRATION_MS) {
      delete captchas[id];
    }
  }

  res.json({ id: captchaId, question: question, timestamp: captchaGenerationTimestamp });
});

app.post('/api/send-saran', validateReferer, suggestionSubmitRateLimiter, async (req, res) => {
  const { nama, saranKritik, captchaId, captchaAnswer, captchaGenerationTime, clientSubmitTimestamp } = req.body;

  if (!captchaId || !captchaAnswer || captchaGenerationTime === undefined || clientSubmitTimestamp === undefined) {
    return res.status(400).json({ error: 'Data captcha dan verifikasi waktu diperlukan.' });
  }

  const storedCaptcha = captchas[captchaId];
  if (!storedCaptcha) {
    return res.status(400).json({ error: 'Captcha tidak valid atau sudah kedaluwarsa. Mohon coba lagi.' });
  }

  if (Date.now() - storedCaptcha.timestamp > CAPTCHA_EXPIRATION_MS) {
    delete captchas[captchaId];
    return res.status(400).json({ error: 'Captcha sudah kedaluwarsa. Mohon coba lagi.' });
  }

  if (storedCaptcha.answer !== captchaAnswer.trim()) {
    delete captchas[captchaId];
    return res.status(400).json({ error: 'Jawaban captcha salah. Mohon coba lagi.' });
  }

  if (Math.abs(captchaGenerationTime - storedCaptcha.timestamp) > TIME_SKEW_TOLERANCE_MS) {
    delete captchas[captchaId];
    return res.status(400).json({ error: 'Verifikasi bot gagal: Perbedaan waktu tidak valid.' });
  }

  const timeSpentOnClient = clientSubmitTimestamp - captchaGenerationTime;

  if (timeSpentOnClient < MIN_CAPTCHA_SOLVE_TIME_MS) {
    delete captchas[captchaId];
    return res.status(400).json({ error: 'Verifikasi bot gagal: Pengiriman terlalu cepat. Mohon coba lagi.' });
  }

  if (timeSpentOnClient > CAPTCHA_EXPIRATION_MS) {
    delete captchas[captchaId];
    return res.status(400).json({ error: 'Verifikasi bot gagal: Pengiriman terlalu lambat atau captcha kedaluwarsa di sisi klien.' });
  }

  delete captchas[captchaId];

  const userAgent = req.headers['user-agent'] || 'unknown';
  const suspiciousUserAgents = [
    'python-requests', 'axios', 'curl', 'wget', 'bot', 'scanner', 'httpclient',
    'headlesschrome', 'phantomjs', 'selenium', 'puppeteer', 'go-http-client',
    'spider', 'crawl', 'validator', 'libwww-perl', 'lwp'
  ];

  if (suspiciousUserAgents.some(ua => userAgent.toLowerCase().includes(ua))) {
    return res.status(403).json({ error: 'Akses ditolak: User-Agent mencurigakan atau tidak valid.' });
  }

  if (!nama || !saranKritik) {
    return res.status(400).json({ error: 'Nama dan Saran & Kritik tidak boleh kosong.' });
  }

  const words = saranKritik.trim().split(/\s+/).filter(word => word.length > 0);
  if (words.length > 60) {
    return res.status(400).json({ error: 'Saran & Kritik maksimal 60 kata.' });
  }

  const newSuggestion = {
    id: Date.now(),
    nama: nama,
    saranKritik: saranKritik,
    timestamp: new Date().toISOString()
  };

  suggestionsCache.push(newSuggestion);
  const success = await updateSuggestionsInBin(suggestionsCache);

  if (success) {
    res.status(200).json({ message: 'Saran berhasil dikirim.' });
  } else {
    suggestionsCache.pop();
    res.status(500).json({ error: 'Gagal menyimpan saran. Silakan coba lagi.' });
  }
});

app.post('/api/view-source', async (req, res) => {
  const { url } = req.body;
  const blocked = blockedServerHosts(req);

  if (!url) {
    return res.status(400).json({ error: 'URL diperlukan.' });
  }

  try {
    const parsedUrl = new URL(url);
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return res.status(400).json({ error: 'Format URL tidak valid. Hanya http:// atau https:// yang didukung.' });
    }
    if (blocked.includes(parsedUrl.hostname.toLowerCase())) {
      return res.status(400).json({ error: 'Mengambil sumber dari domain ini tidak diizinkan.' });
    }
    if (net.isIP(parsedUrl.hostname) !== 0 && (isLocalhostIP(parsedUrl.hostname) || isPrivateIP(parsedUrl.hostname))) {
      return res.status(400).json({ error: 'Mengambil sumber dari resource lokal atau pribadi tidak diizinkan.' });
    }

    const response = await axios.get(url, {
      timeout: 15000,
      validateStatus: status => true
    });
    res.send(response.data);

  } catch (error) {
    let errorMessage = `Gagal mengambil sumber kode: ${error.message}`;
    if (error.code === 'ENOTFOUND' || error.code === 'EAI_AGAIN') {
      errorMessage = `URL tidak ditemukan atau nama host salah.`;
    } else if (error.code === 'ECONNREFUSED') {
      errorMessage = `Koneksi ditolak oleh server target. Mungkin server sedang down atau firewall memblokir.`;
    } else if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      errorMessage = `Permintaan timeout. Server mungkin lambat atau tidak merespons dalam 15 detik.`;
    }
    res.status(500).json({ error: errorMessage });
  }
});

app.post('/api/generate-qris', async (req, res) => {
  const text = req.body.text;
  const color = req.body.color || '#000000';
  const bgColor = req.body.bgColor || '#FFFFFF';
  const size = parseInt(req.body.size, 10) || 256;

  if (!text) {
    return res.status(400).json({ error: 'Teks atau URL untuk QRIS diperlukan' });
  }
  if (text.length > 500) {
    return res.status(400).json({ error: 'Teks terlalu panjang untuk QRIS (maksimal 500 karakter).' });
  }
  try {
    const qrCodeDataUrl = await qrcode.toDataURL(text, {
      errorCorrectionLevel: 'H',
      type: 'image/png',
      size: size,
      color: {
        dark: color,
        light: bgColor
      }
    });
    res.json({ qrCodeDataUrl });
  } catch (err) {
    res.status(500).json({ error: 'Yah, gagal bikin QRIS-nya. Coba lagi nanti ya!' });
  }
});

app.post('/api/encode-base64', (req, res) => {
  const text = req.body.text;
  if (!text) {
    return res.status(400).json({ error: 'Teks untuk di-encode diperlukan.' });
  }
  if (text.length > 10000) {
    return res.status(400).json({ error: 'Teks terlalu panjang untuk di-encode (maksimal 10000 karakter).' });
  }
  try {
    const encoded = Buffer.from(text, 'utf8').toString('base64');
    res.json({ encodedText: encoded });
  } catch (err) {
    res.status(500).json({ error: 'Gagal meng-encode teks. Coba lagi nanti.' });
  }
});

app.post('/api/decode-base64', (req, res) => {
  const base64Text = req.body.text;
  if (!base64Text) {
    return res.status(400).json({ error: 'Teks Base64 untuk di-decode diperlukan.' });
  }
  if (base64Text.length > 15000) {
    return res.status(400).json({ error: 'Teks Base64 terlalu panjang untuk di-decode (maksimal 15000 karakter).' });
  }
  try {
    const decoded = Buffer.from(base64Text, 'base64').toString('utf8');
    res.json({ decodedText: decoded });
  } catch (err) {
    res.status(500).json({ error: 'Gagal men-decode teks. Pastikan itu format Base64 yang valid.' });
  }
});

app.post('/api/check-website-status', async (req, res) => {
  let url = req.body.url;
  const blocked = blockedServerHosts(req);

  if (!url) {
    return res.status(400).json({ error: 'URL website diperlukan.' });
  }
  let targetUrl = url.trim();

  try {
    let parsedUrl = new URL(targetUrl);
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return res.status(400).json({ error: 'Format URL tidak valid. Hanya http:// atau https:// yang didukung.' });
    }
    if (blocked.includes(parsedUrl.hostname.toLowerCase())) {
      return res.status(400).json({ error: 'Mengecek status website ini tidak diizinkan.' });
    }
    if (net.isIP(parsedUrl.hostname) !== 0 && (isLocalhostIP(parsedUrl.hostname) || isPrivateIP(parsedUrl.hostname))) {
      return res.status(400).json({ error: 'Mengecek resource lokal atau pribadi tidak diizinkan.' });
    }
    targetUrl = parsedUrl.toString();
  } catch (e) {
    try {
      let parsedUrl = new URL(`https://${targetUrl}`);
      if (parsedUrl.protocol !== 'https:') {
        return res.status(400).json({ error: 'Format URL tidak valid setelah mencoba https://. Cek lagi ya.' });
      }
      if (blocked.includes(parsedUrl.hostname.toLowerCase())) {
        return res.status(400).json({ error: 'Mengecek status website ini tidak diizinkan.' });
      }
      if (net.isIP(parsedUrl.hostname) !== 0 && (isLocalhostIP(parsedUrl.hostname) || isPrivateIP(parsedUrl.hostname))) {
        return res.status(400).json({ error: 'Mengecek resource lokal atau pribadi tidak diizinkan.' });
      }
      targetUrl = parsedUrl.toString();
    } catch (e2) {
      return res.status(400).json({ error: 'Format URL tidak valid. Cek lagi ya. Pastikan menggunakan http:// atau https://, atau nama domain yang valid.' });
    }
  }

  try {
    const response = await axios.head(targetUrl, { timeout: 10000 });
    res.json({ status: response.status, statusText: response.statusText });
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'EAI_AGAIN') {
      res.status(500).json({ error: `Website tidak ditemukan atau nama host salah.` });
    } else if (error.code === 'ECONNREFUSED') {
      res.status(500).json({ error: `Koneksi ditolak oleh server. Mungkin website sedang down atau firewall.` });
    } else if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      res.status(500).json({ error: `Permintaan timeout. Website mungkin lambat atau tidak merespons.` });
    } else if (error.response) {
      res.json({ status: error.response.status, statusText: error.response.statusText });
    }
    else {
      res.status(500).json({ error: `Gagal mengecek status website: ${error.message}` });
    }
  }
});

app.post('/api/obfuscate-js', (req, res) => {
  const jsCode = req.body.code;

  if (!jsCode || jsCode.trim() === '') {
    return res.status(400).json({ error: 'Kode JavaScript yang akan di-obfuscate diperlukan.' });
  }
  if (jsCode.length > 50000) {
    return res.status(400).json({ error: 'Kode JavaScript terlalu panjang untuk di-obfuscate (maksimal 50000 karakter).' });
  }
  try {
    const obfuscationResult = JavaScriptObfuscator.obfuscate(jsCode, {
      compact: true,
      identifierNamesGenerator: 'hexadecimal',
      simplify: true,
      splitStrings: false,
      stringArray: true,
      target: 'browser',
      transformObjectKeys: false,
      unicodeEscapeSequence: false,
      controlFlowFlattening: false,
      deadCodeInjection: false,
      debugProtection: false,
      disableConsoleOutput: false,
      log: false,
      renameGlobals: false,
      rotateStringArray: true,
      selfDefending: false,
      shuffleStringArray: true,
      stringArrayEncoding: [],
      stringArrayThreshold: 0
    });

    res.json({ obfuscatedCode: obfuscationResult.getObfuscatedCode() });

  } catch (error) {
    res.status(500).json({ error: 'Gagal meng-obfuscate kode JavaScript. Pastikan sintaksnya benar.' });
  }
});

app.post('/api/generate-ascii', (req, res) => {
  const text = req.body.text;
  if (!text || text.trim() === '') {
    return res.status(400).json({ error: 'Teks untuk dikonversi ke ASCII Art diperlukan.' });
  }
  if (text.length > 100) {
    return res.status(400).json({ error: 'Teks terlalu panjang untuk ASCII Art (maksimal 100 karakter).' });
  }

  figlet(text, function(err, data) {
    if (err) {
      return res.status(500).json({ error: 'Gagal menghasilkan ASCII Art. Coba lagi nanti.' });
    }
    res.json({ asciiArt: data });
  });
});

app.post('/api/create-note', validateReferer, noteCreateRateLimiter, async (req, res) => {
  const { title, content, password, captchaId, captchaAnswer, clientVerificationToken } = req.body;

  if (!captchaId || !captchaAnswer || clientVerificationToken === undefined) {
    return res.status(400).json({ error: 'Captcha dan token verifikasi diperlukan.' });
  }

  const storedCaptcha = captchas[captchaId];
  if (!storedCaptcha) {
    return res.status(400).json({ error: 'Captcha tidak valid atau sudah kedaluwarsa. Mohon coba lagi.' });
  }

  if (Date.now() - storedCaptcha.timestamp > CAPTCHA_EXPIRATION_MS) {
    delete captchas[captchaId];
    return res.status(400).json({ error: 'Captcha sudah kedaluwarsa. Mohon coba lagi.' });
  }

  if (storedCaptcha.answer !== captchaAnswer.trim()) {
    delete captchas[captchaId];
    return res.status(400).json({ error: 'Jawaban captcha salah. Mohon coba lagi.' });
  }

  const timeElapsed = Date.now() - storedCaptcha.timestamp;
  const expectedClientVerificationToken = timeElapsed + CLIENT_VERIFICATION_OFFSET;

  if (Math.abs(clientVerificationToken - expectedClientVerificationToken) > CLIENT_VERIFICATION_TOLERANCE_MS) {
    delete captchas[captchaId];
    return res.status(400).json({ error: 'Verifikasi bot gagal. Mohon coba lagi.' });
  }

  delete captchas[captchaId];

  if (!content || content.trim() === '') {
    return res.status(400).json({ error: 'Isi catatan tidak boleh kosong.' });
  }

  const wordCount = content.trim().split(/\s+/).filter(word => word.length > 0).length;
  if (wordCount > 60) {
    return res.status(400).json({ error: 'Isi catatan tidak boleh lebih dari 60 kata.' });
  }
  if (title && title.length > 50) {
    return res.status(400).json({ error: 'Judul catatan tidak boleh lebih dari 50 karakter.' });
  }
  if (password && password.length > 30) {
    return res.status(400).json({ error: 'Password catatan tidak boleh lebih dari 30 karakter.' });
  }

  const noteCode = generateUniqueNoteCode();

  const newNote = {
    title: title || 'Catatan Tanpa Judul',
    content: content.trim(),
    password: password || null,
    createdAt: new Date().toISOString()
  };

  const updatedNotesData = { notes: { ...notesData.notes, [noteCode]: newNote } };

  const success = await updateNotesInBin(updatedNotesData);

  if (success) {
    const shareUrl = `${getBaseUrl(req)}/${noteCode}`;
    res.json({ shareUrl });
  } else {
    res.status(500).json({ error: 'Gagal menyimpan catatan. Silakan coba lagi.' });
  }
});

app.post('/api/get-note', (req, res) => {
  const { code, password } = req.body;

  const note = notesData.notes[code];

  if (!note) {
    return res.status(404).json({ error: 'Catatan tidak ditemukan.' });
  }

  if (note.password && note.password !== password) {
    return res.status(401).json({ error: 'Password salah atau diperlukan.' });
  }

  res.json({
    title: note.title,
    content: note.content
  });
});

app.post('/api/test-api', async (req, res) => {
  const { url, method, headers, body } = req.body;
  const blocked = blockedServerHosts(req);

  if (!url) {
    return res.status(400).json({ error: 'URL API target diperlukan.' });
  }

  let targetUrl = url.trim();
  try {
    let parsedUrl = new URL(targetUrl);
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return res.status(400).json({ error: 'Format URL tidak valid. Hanya http:// atau https:// yang didukung.' });
    }
    if (blocked.includes(parsedUrl.hostname.toLowerCase())) {
      return res.status(400).json({ error: 'Mengecek API di domain ini tidak diizinkan.' });
    }
    if (net.isIP(parsedUrl.hostname) !== 0 && (isLocalhostIP(parsedUrl.hostname) || isPrivateIP(parsedUrl.hostname))) {
      return res.status(400).json({ error: 'Mengecek resource lokal atau pribadi tidak diizinkan.' });
    }
    targetUrl = parsedUrl.toString();
  } catch (e) {
    try {
      let parsedUrl = new URL(`https://${targetUrl}`);
      if (parsedUrl.protocol !== 'https:') {
        return res.status(400).json({ error: 'Format URL tidak valid setelah mencoba https://. Cek lagi ya.' });
      }
      if (blocked.includes(parsedUrl.hostname.toLowerCase())) {
        return res.status(400).json({ error: 'Mengecek API di domain ini tidak diizinkan.' });
      }
      if (net.isIP(parsedUrl.hostname) !== 0 && (isLocalhostIP(parsedUrl.hostname) || isPrivateIP(parsedUrl.hostname))) {
        return res.status(400).json({ error: 'Mengecek resource lokal atau pribadi tidak diizinkan.' });
      }
      targetUrl = parsedUrl.toString();
    } catch (e2) {
      return res.status(400).json({ error: 'Format URL tidak valid. Cek lagi ya. Pastikan menggunakan http:// atau https://, atau nama domain yang valid.' });
    }
  }

  let requestHeaders = {};
  if (headers) {
    try {
      requestHeaders = JSON.parse(headers);
      if (typeof requestHeaders !== 'object' || requestHeaders === null) {
        return res.status(400).json({ error: 'Header harus dalam format JSON objek yang valid.' });
      }
    } catch (e) {
      return res.status(400).json({ error: 'Gagal memparsing header. Pastikan formatnya JSON objek yang valid.' });
    }
  }

  let requestBody = undefined;
  if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE')) {
    try {
      requestBody = JSON.parse(body);
      const contentTypeKey = Object.keys(requestHeaders).find(key => key.toLowerCase() === 'content-type');
      if (!contentTypeKey) {
        requestHeaders['Content-Type'] = 'application/json';
      }
    } catch (e) {
      requestBody = body;
    }
  } else if (body && (method === 'GET' || method === 'HEAD' || method === 'OPTIONS')) {
  }

  const requestConfig = {
    method: method || 'GET',
    url: targetUrl,
    headers: requestHeaders,
    data: requestBody,
    timeout: 15000,
    validateStatus: status => true
  };

  try {
    const response = await axios(requestConfig);
    res.json({
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
      body: response.data
    });
  } catch (error) {
    let errorMessage = `Gagal melakukan permintaan API: ${error.message}`;
    if (error.code === 'ENOTFOUND' || error.code === 'EAI_AGAIN') {
      errorMessage = `URL tidak ditemukan atau nama host salah.`;
    } else if (error.code === 'ECONNREFUSED') {
      errorMessage = `Koneksi ditolak oleh server target. Mungkin API sedang down atau firewall memblokir.`
    } else if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      errorMessage = `Permintaan timeout. API target mungkin lambat atau tidak merespons dalam 15 detik.`;
    } else if (error.response) {
      errorMessage = `Mendapatkan status code ${error.response.status}: ${error.response.statusText}. Lihat detail respons di bawah.`;
      return res.json({
        status: error.response.status,
        statusText: error.response.statusText,
        headers: error.response.headers,
        body: error.response.data,
        error: errorMessage
      });
    }
    res.status(500).json({ error: errorMessage });
  }
});

app.post('/api/dns-lookup', async (req, res) => {
  const domain = req.body.domain;
  const blocked = blockedServerHosts(req);

  if (!domain || domain.trim() === '') {
    return res.status(400).json({ error: 'Nama domain atau host diperlukan.' });
  }

  const targetDomain = domain.trim().toLowerCase();

  if (blocked.includes(targetDomain) || blocked.some(blockedHost => targetDomain.endsWith(`.${blockedHost}`))) {
    return res.status(400).json({ error: 'Mencari DNS untuk domain ini atau subdomainnya tidak diizinkan.' });
  }

  if (net.isIP(targetDomain) !== 0 && (isLocalhostIP(targetDomain) || isPrivateIP(targetDomain))) {
    return res.status(400).json({ error: 'Mencari DNS untuk IP lokal atau pribadi tidak diizinkan.' });
  }

  const lookupTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'];
  const results = {};
  let hasResults = false;

  for (const type of lookupTypes) {
    try {
      let records;
      if (type === 'MX') {
        records = await dns.resolveMx(targetDomain);
        records = records.map(rec => ({ exchange: rec.exchange, priority: rec.priority }));
      } else if (type === 'TXT') {
        records = await dns.resolveTxt(targetDomain);
        records = records.map(rec => rec.join(''));
      }
      else {
        records = await dns.resolve(targetDomain, type);
      }
      if (records && records.length > 0) {
        results[type] = records;
        hasResults = true;
      }
    } catch (err) {
    }
  }

  if (hasResults) {
    res.json(results);
  } else {
    res.status(404).json({ error: `Tidak ada record DNS yang ditemukan untuk ${targetDomain} atau terjadi kesalahan saat lookup. Cek nama domain dan coba lagi.` });
  }
});

app.post('/api/check-port', async (req, res) => {
  const { host, port } = req.body;
  const blocked = blockedServerHosts(req);

  if (!host || !port) {
    return res.status(400).json({ error: 'Domain/IP dan nomor port diperlukan.' });
  }

  const parsedPort = parseInt(port, 10);
  if (isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
    return res.status(400).json({ error: 'Port harus berupa angka antara 1 dan 65535.' });
  }

  const targetHost = host.trim().toLowerCase();

  if (blocked.includes(targetHost)) {
    return res.status(400).json({ error: 'Mengecek port untuk domain ini tidak diizinkan.' });
  }

  let resolvedAddress = targetHost;

  if (net.isIP(targetHost) === 0) {
    try {
      const { address } = await dns.lookup(targetHost);
      resolvedAddress = address;
    } catch (error) {
      if (error.code === 'ENOTFOUND' || error.code === 'EAI_AGAIN') {
        return res.status(400).json({ error: `Nama host "${targetHost}" tidak dapat di-resolve. Cek penulisan domain.` });
      }
      return res.status(500).json({ error: 'Gagal me-resolve nama host.' });
    }
  }

  if (isLocalhostIP(resolvedAddress) || isPrivateIP(resolvedAddress)) {
    return res.status(400).json({ error: 'Mengecek port untuk IP lokal atau pribadi tidak diizinkan.' });
  }

  const socket = new net.Socket();
  const timeout = 5000;

  let checkFinished = false;

  try {
    const result = await new Promise((resolve, reject) => {
      socket.setTimeout(timeout);

      socket.on('connect', () => {
        socket.destroy();
        if (!checkFinished) {
          checkFinished = true;
          resolve({ isOpen: true, message: `Port ${parsedPort} di ${host} TERBUKA.` });
        }
      });

      socket.on('timeout', () => {
        socket.destroy();
        if (!checkFinished) {
          checkFinished = true;
          resolve({ isOpen: false, message: `Port ${parsedPort} di ${host} DITUTUP atau tidak merespons (timeout ${timeout / 1000}s).` });
        }
      });

      socket.on('error', (err) => {
        socket.destroy();
        if (!checkFinished) {
          checkFinished = true;
          if (err.code === 'ECONNREFUSED') {
            resolve({ isOpen: false, message: `Port ${parsedPort} di ${host} DITUTUP (koneksi ditolak).` });
          } else if (err.code === 'EHOSTUNREACH' || err.code === 'ENETUNREACH' || err.code === 'EADDRNOTAVAIL') {
            resolve({ isOpen: false, message: `Host ${host} tidak bisa dijangkau atau tidak ada.` });
          } else if (err.code === 'ETIMEDOUT') {
            resolve({ isOpen: false, message: `Port ${parsedPort} di ${host} DITUTUP atau tidak merespons (timeout ${timeout / 1000}s).` });
          }
          else {
            reject(new Error(`Terjadi kesalahan saat memeriksa port: ${err.message}`));
          }
        }
      });

      socket.connect(parsedPort, resolvedAddress);
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message || 'Gagal melakukan cek port.' });
  }
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: `API endpoint ${req.method} ${req.originalUrl} not found.` });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  figlet('FreeTools', function(err, data) {
    if (!err) {
      console.log(data);
      console.log(`Server is running on port ${PORT}`);
    }
  });
});