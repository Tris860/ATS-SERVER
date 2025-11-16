// server.js
const http = require('http');
const os = require('os');
const url = require('url');

const WebSocket = require('ws');
const fetch = require('node-fetch');

// Config via env vars (set in Render Dashboard)
const PORT = process.env.PORT || 4000;
const WEMOS_AUTH_URL = process.env.WEMOS_AUTH_URL || 'https://tristechhub.org.rw/projects/ATS/backend/main.php?action=wemos_auth';
const PHP_BACKEND_URL = process.env.PHP_BACKEND_URL || 'https://tristechhub.org.rw/projects/ATS/backend/main.php?action=is_current_time_in_period';
const USER_DEVICE_LOOKUP_URL = process.env.USER_DEVICE_LOOKUP_URL || 'https://tristechhub.org.rw/projects/ATS/backend/main.php?action=get_user_device';

const wss = new WebSocket.Server({ noServer: true });

// Maps (unchanged)
const authenticatedWemos = new Map();
const userWebClients = new Map();
const userToWemosCache = new Map();

function logNetworkAddresses() {
  const interfaces = os.networkInterfaces();
  console.log('\n--- Available Server IP Addresses ---');
  for (const name in interfaces) {
    for (const net of interfaces[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        console.log(`[${name}]: ${net.address}`);
      }
    }
  }
  console.log('-------------------------------------\n');
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

    if (!resp.ok) throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
    const ct = resp.headers.get('content-type') || '';
    if (!ct.includes('application/json')) throw new Error('Expected application/json');

    const data = await resp.json();
    if (data.success === true && data.device_name) {
      userToWemosCache.set(userEmail, data.device_name);
      return data.device_name;
    } else {
      return null;
    }
  } catch (err) {
    console.error('getCachedWemosDeviceNameForUser error:', err.message);
    return null;
  }
}

// Add webpage client socket to the user set
function addWebClientForUser(email, ws) {
  if (!email) return;
  let set = userWebClients.get(email);
  if (!set) {
    set = new Set();
    userWebClients.set(email, set);
  }
  set.add(ws);
}

// Remove webpage client socket from the user set
function removeWebClientForUser(email, ws) {
  if (!email) return;
  const set = userWebClients.get(email);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) userWebClients.delete(email);
}

// Notify all webpage clients for a user
function notifyWebClients(email, message) {
  const set = userWebClients.get(email);
  if (!set) return;
  set.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      try { client.send(message); } catch (e) { /* ignore per-client send error */ }
    }
  });
}

// Authenticate Wemos (calls PHP) then upgrade socket
async function authenticateAndUpgradeWemos(request, socket, head) {
  const usernameHeader = request.headers['x-username'];
  const passwordHeader = request.headers['x-password'];
  console.log(`Authenticating Wemos. username=${usernameHeader}`);

  if (!usernameHeader || !passwordHeader) {
    try { socket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch (e) {}
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

    if (!resp.ok) {
      try { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); } catch (e) {}
      socket.destroy();
      console.log(`Authenticating Wemos. Failed due to status`);
      return;
    }

    const ct = resp.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
      try { socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); } catch (e) {}
      console.log(`Authenticating Wemos. Failed due to bad response`);
      socket.destroy();
      return;
    }

    const data = await resp.json();
    if (data.success !== true) {
      try { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); } catch (e) {}
      console.log(`Authenticating Wemos. Failed due to bad credentials`, data.message);
      socket.destroy();
      return;
    }

    // deviceName is authoritative label for the physical device
    const deviceName = data.data?.device_name || usernameHeader;
    const initialCommand = data.data?.hard_switch_enabled ? 'HARD_ON' : 'HARD_OFF';
    console.log(data.data?.hard_switch_enabled, initialCommand);
    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.isWemos = true;
      ws.wemosName = deviceName;
      ws.isAlive = true;

      // If there's an existing Wemos connection for same deviceName, terminate it and replace.
      const existing = authenticatedWemos.get(deviceName);
      if (existing && existing.readyState === WebSocket.OPEN) {
        try { existing.terminate(); } catch (e) {}
      }

      authenticatedWemos.set(deviceName, ws);
      console.log(`Wemos client '${deviceName}' authenticated and connected.`);

      // Send initial command if any
      if (initialCommand) {
        try { ws.send(initialCommand); console.log(`Sent initial command to Wemos '${deviceName}': ${initialCommand}`); } catch (e) {}
      }

      // Notify all webpage clients that map to the owner(s) of this device.
      userWebClients.forEach((set, email) => {
        const mapped = userToWemosCache.get(email);
        if (mapped === deviceName) {
          set.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
              try { client.send('WEMOS_STATUS:CONNECTED'); } catch (e) {}
            }
          });
        }
      });

      wss.emit('connection', ws, request);
    });

  } catch (err) {
    console.error(`Authentication error for Wemos '${usernameHeader}':`, err.message);
    try { socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n'); } catch (e) {}
    socket.destroy();
  }
}

// HTTP server + upgrade handling
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('WebSocket server running\n');
});

// **RENDER FIX**: Handle upgrades on the HTTP server
server.on('upgrade', async (request, socket, head) => {
  const parsed = url.parse(request.url, true);
  const webUserQuery = parsed.query.user || null;

  const xUsername = request.headers['x-username'];
  const xPassword = request.headers['x-password'];

  // Wemos (ESP) uses custom headers for authentication
  if (xUsername && xPassword) {
    await authenticateAndUpgradeWemos(request, socket, head);
    return;
  }

  // Browser/webpage client
  wss.handleUpgrade(request, socket, head, (ws) => {
    ws.isWemos = false;
    ws.webUsername = webUserQuery; // user email, NOT device name
    ws.assignedWemosName = null;
    ws.isAlive = true;
    console.log(`Webpage client connected. user=${ws.webUsername}`);
    wss.emit('connection', ws, request);
  });
});

// Connection handling for both Wemos and webpage clients
wss.on('connection', (ws, request) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  // Webpage client: resolve its assigned device and register into userWebClients set
  if (!ws.isWemos) {
    const userEmail = ws.webUsername;
    if (userEmail) {
      addWebClientForUser(userEmail, ws);

      // Resolve device mapping and notify immediate status
      getCachedWemosDeviceNameForUser(userEmail).then((deviceName) => {
        ws.assignedWemosName = deviceName;
        const wemosSocket = deviceName ? authenticatedWemos.get(deviceName) : null;
        const status = (wemosSocket && wemosSocket.readyState === WebSocket.OPEN) ? 'CONNECTED' : 'DISCONNECTED';
        try { ws.send(`WEMOS_STATUS:${status}`); } catch (e) {}
        console.log(`Mapped webpage '${userEmail}' -> device '${deviceName}', status=${status}`);
      }).catch((err) => {
        try { ws.send('WEMOS_STATUS:DISCONNECTED'); } catch (e) {}
        console.error('Error mapping user to device:', err.message);
      });
    } else {
      // No identity provided from browser
      try { ws.send('WEMOS_STATUS:DISCONNECTED'); } catch (e) {}
    }
  }

  // Message handling
  ws.on('message', async (msg) => {
    const text = msg.toString();

    if (!ws.isWemos) {
      // Webpage -> server forwarding to assigned Wemos
      const userEmail = ws.webUsername;
      if (!userEmail) {
        try { ws.send('MESSAGE_FAILED:NoUserIdentity'); } catch (e) {}
        return;
      }

      // Ensure assignedWemosName is known (should be set on connect); fallback to resolve now
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
        try {
          // Forward raw message to Wemos
          target.send(text);
          try { ws.send('MESSAGE_DELIVERED'); } catch (e) {}
          console.log(`Delivered message from '${userEmail}' to Wemos '${deviceName}': ${text}`);
        } catch (err) {
          try { ws.send('MESSAGE_FAILED'); } catch (e) {}
          console.error('Error sending message to Wemos:', err.message);
        }
      } else {
        try { ws.send('WEMOS_STATUS:DISCONNECTED'); } catch (e) {}
        console.warn(`Attempt to send to disconnected Wemos '${deviceName}'`);
      }
    } else {
      // Wemos -> server: forward to all webpage clients for mapped user(s)
      const fromDevice = ws.wemosName;
      console.log(`Message from Wemos '${fromDevice}': ${text}`);

      // Send to any webpage client whose cached mapping points to this device
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
      // remove Wemos socket
      const current = authenticatedWemos.get(name);
      if (current === ws) authenticatedWemos.delete(name);

      console.log(`Wemos '${name}' disconnected.`);
      // Notify pages mapping to this device
      userWebClients.forEach((set, email) => {
        if (userToWemosCache.get(email) === name) {
          set.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
              try { client.send('WEMOS_STATUS:DISCONNECTED'); } catch (e) {}
            }
          });
        }
      });
    } else {
      // A webpage closed: remove from its user set
      const email = ws.webUsername;
      if (email) {
        removeWebClientForUser(email, ws);
        console.log(`Webpage client disconnected. user=${email}`);
      } else {
        console.log('Webpage client disconnected. user=[unknown]');
      }
    }
  });

  ws.on('error', (err) => {
    console.error('WebSocket error:', err.message);
  });
});

// Heartbeat: detect dead sockets
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      try { ws.terminate(); } catch (e) {}
      return;
    }
    ws.isAlive = false;
    try { ws.ping(); } catch (e) {}
  });
}, 30000);

// Periodic PHP backend check and broadcast
async function checkPhpBackend() {
  try {
    const resp = await fetch(PHP_BACKEND_URL);
    if (!resp.ok) throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
    const ct = resp.headers.get('content-type') || '';
    if (!ct.includes('application/json')) throw new Error('Expected application/json');

    const data = await resp.json();
    if (data.success === true) {
      const messageToWemos = 'AUTO_ON';
      const messageToWeb = 'TIME_MATCHED: '+data.message+": "+ data.id;

      // Broadcast AUTO_ON to all connected Wemos
      authenticatedWemos.forEach((client, deviceName) => {
        if (client && client.readyState === WebSocket.OPEN) {
          try { client.send(messageToWemos); console.log(`Sent ${messageToWemos} to ${deviceName}`); } catch (e) {}
        }
      });

      // Notify webpages (they will compare mapping)
      userWebClients.forEach((set) => {
        set.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            try { client.send(messageToWeb); } catch (e) {}
          }
        });
      });
    }
  } catch (err) {
    console.error('checkPhpBackend error:', err.message);
  }
}

// **RENDER FIX**: Bind to PORT and 0.0.0.0
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server listening on port ${PORT}`);
  logNetworkAddresses();
  checkPhpBackend();
  setInterval(checkPhpBackend, 60000);
});