// server.js
const http = require('http');
const os = require('os');
const url = require('url');

const WebSocket = require('ws');
const fetch = require('node-fetch');

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

function enqueueForDevice(deviceName, msg) {
  let q = pendingQueues.get(deviceName) || [];
  q.push(msg);
  pendingQueues.set(deviceName, q);
}

function flushQueue(ws) {
  const deviceName = ws.wemosName;
  const q = pendingQueues.get(deviceName) || [];
  pendingQueues.delete(deviceName);
  q.forEach(m => {
    try { ws.send(m); } catch (e) {}
  });
  if (q.length > 0) log(`Flushed ${q.length} queued messages to ${deviceName}`);
}

// === SERVER ===
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('WebSocket server running\n');
});

server.on('upgrade', async (request, socket, head) => {
  const parsed = url.parse(request.url, true);
  const webUserQuery = parsed.query.user || null;

  const xUsername = request.headers['x-username'];
  const xPassword = request.headers['x-password'];

  if (xUsername && xPassword) {
    await authenticateAndUpgradeWemos(request, socket, head);
  } else {
    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.isWemos = false;
      ws.webUsername = webUserQuery;
      ws.assignedWemosName = null;
      ws.isAlive = true;
      log(`Webpage client connected. user=${ws.webUsername || '[unknown]'}`);
      wss.emit('connection', ws, request);
    });
  }
});

// === AUTHENTICATE WEMOS ===
async function authenticateAndUpgradeWemos(request, socket, head) {
  const usernameHeader = request.headers['x-username'];
  const passwordHeader = request.headers['x-password'];
  log(`Authenticating Wemos. username=${usernameHeader}`);

  if (!usernameHeader || !passwordHeader) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return;
  }

  try {
    const postData = new URLSearchParams();
    postData.append('action', 'wemos_auth');
    postData.append('username', usernameHeader);
    postData.append('password', passwordHeader);

    const resp = await fetch(WEMOS_AUTH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: postData.toString()
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    if (data.success !== true) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      log(`Wemos auth failed: ${data.message || 'invalid'}`);
      return;
    }

    const deviceName = data.data?.device_name || usernameHeader;
    const initialCommand = data.data?.hard_switch_enabled ? 'HARD_ON' : 'HARD_OFF';

    log(`Wemos '${deviceName}' TLS handshake started`);
    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.isWemos = true;
      ws.wemosName = deviceName;
      ws.isAlive = true;
      ws.connectTime = Date.now();

      const existing = authenticatedWemos.get(deviceName);
      if (existing && existing.readyState === WebSocket.OPEN) {
        existing.terminate();
      }

      authenticatedWemos.set(deviceName, ws);
      log(`Wemos '${deviceName}' authenticated and CONNECTED`);

      if (initialCommand) enqueueForDevice(deviceName, initialCommand);
      flushQueue(ws);

      notifyDeviceStatusToWebClients(deviceName, 'CONNECTED');
      wss.emit('connection', ws, request);
    });

  } catch (err) {
    log(`Wemos auth error: ${err.message}`);
    socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
    socket.destroy();
  }
}

// === HELPERS ===
function addWebClientForUser(email, ws) {
  if (!email) return;
  let set = userWebClients.get(email) || new Set();
  set.add(ws);
  userWebClients.set(email, set);
}

function removeWebClientForUser(email, ws) {
  const set = userWebClients.get(email);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) userWebClients.delete(email);
}

function notifyDeviceStatusToWebClients(deviceName, status) {
  userWebClients.forEach((set, email) => {
    if (userToWemosCache.get(email) === deviceName) {
      set.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          try { client.send(`WEMOS_STATUS:${status}`); } catch (e) {}
        }
      });
    }
  });
}

async function getCachedWemosDeviceNameForUser(userEmail) {
  if (!userEmail) return null;
  if (userToWemosCache.has(userEmail)) return userToWemosCache.get(userEmail);

  const postData = new URLSearchParams();
  postData.append('action', 'get_user_device');
  postData.append('email', userEmail);

  try {
    const resp = await fetch(USER_DEVICE_LOOKUP_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: postData.toString()
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    if (data.success && data.device_name) {
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

      if (!deviceName) return;

      const target = authenticatedWemos.get(deviceName);
      if (target && target.readyState === WebSocket.OPEN) {
        const age = Date.now() - (target.connectTime || 0);
        if (age < 8000) {
          enqueueForDevice(deviceName, text);
        } else {
          try { target.send(text); } catch (e) {}
        }
        try { ws.send('MESSAGE_DELIVERED'); } catch (e) {}
      } else {
        enqueueForDevice(deviceName, text);
        try { ws.send('WEMOS_STATUS:DISCONNECTED'); } catch (e) {}
      }
    } else {
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
      }
    }
  });

  ws.on('error', (err) => log(`WebSocket error: ${err.message}`));
});

// === HEARTBEAT ===
setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

// === PERIODIC PHP CHECK ===
async function checkPhpBackend() {
  try {
    const resp = await fetch(PHP_BACKEND_URL);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    if (data.success === true) {
      const messageToWemos = 'AUTO_ON';
      const messageToWeb = `TIME_MATCHED: ${data.message}: ${data.id}`;

      authenticatedWemos.forEach((client, deviceName) => {
        if (client && client.readyState === WebSocket.OPEN) {
          const age = Date.now() - (client.connectTime || 0);
          if (age < 8000) {
            enqueueForDevice(deviceName, messageToWemos);
          } else {
            try { client.send(messageToWemos); } catch (e) {}
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