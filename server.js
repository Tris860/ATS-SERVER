// server.js (hardened)
/* eslint-disable no-console */
const http = require('http');
const os = require('os');
const url = require('url');
const WebSocket = require('ws');

// === FETCH SAFETY (use global fetch when available, otherwise try node-fetch) ===
let fetchFn = global.fetch;
if (!fetchFn) {
  try {
    // try commonjs node-fetch v2 fallback
    // if your environment only supports node-fetch v3 (ESM) this will fail;
    // however Render / modern Node usually has global fetch.
    // Keep this in try/catch to avoid crashing.
    fetchFn = require('node-fetch');
  } catch (e) {
    console.warn('fetch not available and node-fetch not found; remote calls will fail unless Node provides fetch');
    fetchFn = undefined;
  }
}

// === CONFIG (use env vars on Render) ===
const PORT = process.env.PORT || 4000;
const WEMOS_AUTH_URL = process.env.WEMOS_AUTH_URL || 'https://tristechhub.org.rw/projects/ATS/backend/main.php?action=wemos_auth';
const PHP_BACKEND_URL = process.env.PHP_BACKEND_URL || 'https://tristechhub.org.rw/projects/ATS/backend/main.php?action=is_current_time_in_period';
const USER_DEVICE_LOOKUP_URL = process.env.USER_DEVICE_LOOKUP_URL || 'https://tristechhub.org.rw/projects/ATS/backend/main.php?action=get_user_device';

const wss = new WebSocket.Server({ noServer: true });

// === STATE MAPS ===
const authenticatedWemos = new Map();      // deviceName → ws
const userWebClients = new Map();          // email → Set(ws)
const userToWemosCache = new Map();        // email → deviceName
const pendingQueues = new Map();           // deviceName → string[] (queued commands)

// === UTILS ===
function log(msg) {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}

function safeSocketWrite(socket, payload) {
  try {
    socket.write(payload);
  } catch (e) {
    // ignore; socket may be already closed
  }
}

function normalizeHeader(h) {
  if (!h) return null;
  if (Array.isArray(h)) {
    // prefer first non-empty
    for (const v of h) {
      if (v && v.toString().trim()) return v.toString().trim();
    }
    return null;
  }
  // header might be comma separated string when duplicates exist
  if (typeof h === 'string') {
    const parts = h.split(',');
    return parts.length ? parts[0].trim() : h.trim();
  }
  return String(h);
}

function enqueueForDevice(deviceName, msg) {
  if (!deviceName) return;
  const q = pendingQueues.get(deviceName) || [];
  q.push(msg);
  pendingQueues.set(deviceName, q);
}

function flushQueue(ws) {
  if (!ws || !ws.wemosName) return;
  const deviceName = ws.wemosName;
  const q = pendingQueues.get(deviceName) || [];
  pendingQueues.delete(deviceName);
  let sent = 0;
  q.forEach(m => {
    try {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(m);
        sent++;
      } else {
        // re-enqueue if not open
        enqueueForDevice(deviceName, m);
      }
    } catch (e) {
      // ignore single send errors
      enqueueForDevice(deviceName, m);
    }
  });
  if (sent > 0) log(`Flushed ${sent} queued messages to ${deviceName}`);
}

// === HTTP SERVER & UPGRADE HANDLING ===
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('WebSocket server running\n');
});

server.on('upgrade', async (request, socket, head) => {
  const parsed = url.parse(request.url, true);
  const webUserQuery = parsed.query.user || null;

  const rawUsername = request.headers['x-username'];
  const rawPassword = request.headers['x-password'];

  const xUsername = normalizeHeader(rawUsername);
  const xPassword = normalizeHeader(rawPassword);

  // If the client sent auth headers, treat as Wemos device
  if (xUsername && xPassword) {
    await authenticateAndUpgradeWemos(request, socket, head, xUsername, xPassword);
    return;
  }

  // Otherwise treat as a regular browser/web client
  try {
    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.isWemos = false;
      ws.webUsername = webUserQuery;
      ws.assignedWemosName = null;
      ws.isAlive = true;
      log(`Webpage client connected. user=${ws.webUsername || '[unknown]'}`);
      wss.emit('connection', ws, request);
    });
  } catch (err) {
    log(`Upgrade error for webpage client: ${err.message}`);
    safeSocketWrite(socket, 'HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
  }
});

// === AUTHENTICATE WEMOS ===
async function authenticateAndUpgradeWemos(request, socket, head, usernameHeader, passwordHeader) {
  log(`Authenticating Wemos. username=${usernameHeader}`);

  if (!usernameHeader || !passwordHeader) {
    safeSocketWrite(socket, 'HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return;
  }

  if (!fetchFn) {
    log('ERROR: fetch not available in this Node runtime');
    safeSocketWrite(socket, 'HTTP/1.1 500 Internal Server Error\r\n\r\n');
    socket.destroy();
    return;
  }

  try {
    const postData = new URLSearchParams();
    postData.append('action', 'wemos_auth');
    postData.append('username', usernameHeader);
    postData.append('password', passwordHeader);

    const resp = await fetchFn(WEMOS_AUTH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: postData.toString()
    });

    if (!resp.ok) {
      log(`Wemos auth HTTP error: ${resp.status} ${resp.statusText || ''}`);
      safeSocketWrite(socket, 'HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    // try to parse JSON, but be defensive
    let data = null;
    const ct = resp.headers.get ? resp.headers.get('content-type') || '' : '';
    if (ct.includes('application/json')) {
      data = await resp.json();
    } else {
      const raw = await resp.text();
      log(`WEMOS AUTH RAW RESPONSE: ${raw.slice(0, 1000)}`); // log up to 1000 chars
      try {
        data = JSON.parse(raw);
      } catch (e) {
        log('Wemos auth returned non-json response; rejecting auth');
        safeSocketWrite(socket, 'HTTP/1.1 502 Bad Gateway\r\n\r\n');
        socket.destroy();
        return;
      }
    }

    if (!data || data.success !== true) {
      log(`Wemos auth failed: ${data && data.message ? data.message : 'invalid credentials'}`);
      safeSocketWrite(socket, 'HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    console.log(data.message);
    // deviceName is authoritative label for the physical device
    const deviceName = data.data?.device_name || usernameHeader;
    const initialCommand = data.data?.hard_switch_enabled ? 'HARD_ON' : 'HARD_OFF';

    // Proceed with WS upgrade
    try {
      wss.handleUpgrade(request, socket, head, (ws) => {
        ws.isWemos = true;
        ws.wemosName = deviceName;
        ws.isAlive = true;
        ws.connectTime = Date.now();

        // If there's an existing Wemos connection for same deviceName, terminate it
        const existing = authenticatedWemos.get(deviceName);
        if (existing && existing.readyState === WebSocket.OPEN) {
          try { existing.terminate();console.log(`Terminated existing Wemos connection for ${deviceName}`); } catch (e) { console.log(`Error terminating existing Wemos connection for ${deviceName}: ${e.message}`); }
        }

        authenticatedWemos.set(deviceName, ws);
        console.log(`Wemos '${deviceName}' authenticated and connected.`);
        log(`Wemos '${deviceName}' authenticated and connected.`);

        // enqueue initial command so it will be flushed once client is ready
        if (initialCommand) enqueueForDevice(deviceName, initialCommand);

        // notify web clients mapped to this device that it's connected
        notifyDeviceStatusToWebClients(deviceName, 'CONNECTED');

        // flush queued messages
        flushQueue(ws);

        wss.emit('connection', ws, request);
      });
    } catch (err) {
      console.log(`handleUpgrade error: ${err.message}`);
      log(`handleUpgrade error: ${err.message}`);
      safeSocketWrite(socket, 'HTTP/1.1 500 Internal Server Error\r\n\r\n');
      socket.destroy();
    }

  } catch (err) {
    log(`Wemos auth error: ${err.message}`);
    safeSocketWrite(socket, 'HTTP/1.1 500 Internal Server Error\r\n\r\n');
    socket.destroy();
  }
}

// === HELPERS FOR WEB CLIENT MANAGEMENT ===
function addWebClientForUser(email, ws) {
  if (!email) return;
  let set = userWebClients.get(email);
  if (!set) {
    set = new Set();
    userWebClients.set(email, set);
  }
  set.add(ws);
}

function removeWebClientForUser(email, ws) {
  const set = userWebClients.get(email);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) userWebClients.delete(email);
}

function notifyDeviceStatusToWebClients(deviceName, status) {
  userWebClients.forEach((set, email) => {
    try {
      if (userToWemosCache.get(email) === deviceName) {
        set.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            try { client.send(`WEMOS_STATUS:${status}`); } catch (e) {}
          }
        });
      }
    } catch (e) {
      // continue on any per-user error
    }
  });
}

async function getCachedWemosDeviceNameForUser(userEmail) {
  if (!userEmail) return null;
  if (userToWemosCache.has(userEmail)) return userToWemosCache.get(userEmail);

  if (!fetchFn) {
    log('fetch unavailable, cannot lookup user device');
    return null;
  }

  const postData = new URLSearchParams();
  postData.append('action', 'get_user_device');
  postData.append('email', userEmail);

  try {
    const resp = await fetchFn(USER_DEVICE_LOOKUP_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: postData.toString()
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    if (data && data.success && data.device_name) {
      userToWemosCache.set(userEmail, data.device_name);
      return data.device_name;
    }
  } catch (err) {
    log(`get_user_device error: ${err.message}`);
  }
  return null;
}

// === CONNECTION HANDLER ===
wss.on('connection', (ws, request) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  if (!ws.isWemos) {
    const userEmail = ws.webUsername;
    if (userEmail) {
      addWebClientForUser(userEmail, ws);
      getCachedWemosDeviceNameForUser(userEmail).then(deviceName => {
        ws.assignedWemosName = deviceName;
        const status = (deviceName && authenticatedWemos.get(deviceName)?.readyState === WebSocket.OPEN) ? 'CONNECTED' : 'DISCONNECTED';
        try { ws.send(`WEMOS_STATUS:${status}`); } catch (e) {}
      }).catch(err => {
        try { ws.send('WEMOS_STATUS:DISCONNECTED'); } catch (e) {}
      });
    } else {
      try { ws.send('WEMOS_STATUS:DISCONNECTED'); } catch (e) {}
    }
  }

  ws.on('message', async (msg) => {
    const text = msg.toString().trim();

    if (!ws.isWemos) {
      const userEmail = ws.webUsername;
      if (!userEmail) return;

      let deviceName = ws.assignedWemosName;
      if (!deviceName) {
        deviceName = await getCachedWemosDeviceNameForUser(userEmail);
        ws.assignedWemosName = deviceName;
      }

      if (!deviceName) {
        try { ws.send('MESSAGE_FAILED:NoDeviceAssigned'); } catch (e) {}
        return;
      }

      const target = authenticatedWemos.get(deviceName);
      if (target && target.readyState === WebSocket.OPEN) {
        const age = Date.now() - (target.connectTime || 0);
        if (age < 8000) {
          enqueueForDevice(deviceName, text);
        } else {
          try { target.send(text); } catch (e) { enqueueForDevice(deviceName, text); }
        }
        try { ws.send('MESSAGE_DELIVERED'); } catch (e) {}
      } else {
        enqueueForDevice(deviceName, text);
        try { ws.send('WEMOS_STATUS:DISCONNECTED'); } catch (e) {}
      }
    } else {
      // Wemos -> server messages
      const fromDevice = ws.wemosName;
      if (text === "WEMOS_READY") {
        flushQueue(ws);
        return;
      }

      userWebClients.forEach((set, email) => {
        if (userToWemosCache.get(email) === fromDevice) {
          set.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
              try { client.send(`WEMOS_MSG:${text}`); } catch (e) {}
            }
          });
        }
      });
    }
  });

  ws.on('close', () => {
    if (ws.isWemos && ws.wemosName) {
      const name = ws.wemosName;
      if (authenticatedWemos.get(name) === ws) authenticatedWemos.delete(name);
      log(`Wemos '${name}' disconnected.`);
      notifyDeviceStatusToWebClients(name, 'DISCONNECTED');
    } else {
      const email = ws.webUsername;
      if (email) {
        removeWebClientForUser(email, ws);
        log(`Webpage client disconnected. user=${email}`);
      } else {
        log('Webpage client disconnected. user=[unknown]');
      }
    }
  });

  ws.on('error', (err) => log(`WebSocket error: ${err && err.message ? err.message : JSON.stringify(err)}`));
});

// === HEARTBEAT ===
setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    try { ws.ping(); } catch (e) {}
  });
}, 30000);

// === PERIODIC PHP CHECK ===
async function checkPhpBackend() {
  if (!fetchFn) return;
  try {
    const resp = await fetchFn(PHP_BACKEND_URL);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    if (data && data.success === true) {
      const messageToWemos = 'AUTO_ON';
      const messageToWeb = `TIME_MATCHED: ${data.message}: ${data.id}`;

      authenticatedWemos.forEach((client, deviceName) => {
        if (client && client.readyState === WebSocket.OPEN) {
          const age = Date.now() - (client.connectTime || 0);
          if (age < 8000) {
            enqueueForDevice(deviceName, messageToWemos);
          } else {
            try { client.send(messageToWemos); } catch (e) { enqueueForDevice(deviceName, messageToWemos); }
          }
        } else {
          enqueueForDevice(deviceName, messageToWemos);
        }
      });

      userWebClients.forEach(set => {
        set.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            try { client.send(messageToWeb); } catch (e) {}
          }
        });
      });
    }
  } catch (err) {
    log(`checkPhpBackend error: ${err.message}`);
  }
}

// === START ===
server.listen(PORT, '0.0.0.0', () => {
  log(`Server running on port ${PORT}`);
  checkPhpBackend();
  setInterval(checkPhpBackend, 60000);
});
