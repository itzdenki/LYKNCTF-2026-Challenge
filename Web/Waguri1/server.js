const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { WebSocket, WebSocketServer } = require('ws');

const ROOT_DIR = __dirname;
const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const IMAGES_DIR = path.join(ROOT_DIR, 'images');
const SOUNDS_DIR = path.join(ROOT_DIR, 'sounds');

const DEFAULT_PORT = Number.parseInt(process.env.PORT || '3000', 10);
const DEFAULT_FLAG = 'LYKNCTF{W4GUR1_1N_TH3_S0CK3T}';
const DEFAULT_RACE_THRESHOLD = Number.parseInt(process.env.RACE_THRESHOLD || '6', 10);
const DEFAULT_PRELOCK_DELAY_MS = Number.parseInt(process.env.PRELOCK_DELAY_MS || '80', 10);
const DEFAULT_SPAWN_DELAY_MS = Number.parseInt(process.env.SPAWN_DELAY_MS || '120', 10);

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.gif': 'image/gif',
  '.mp3': 'audio/mpeg'
};

const collator = new Intl.Collator('en', {
  numeric: true,
  sensitivity: 'base'
});

function listAssets(directory, extension, urlPrefix) {
  return fs
    .readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .filter((name) => path.extname(name).toLowerCase() === extension)
    .sort((left, right) => collator.compare(left, right))
    .map((name) => `${urlPrefix}/${name}`);
}

function loadAssets() {
  const images = listAssets(IMAGES_DIR, '.gif', '/images');
  const sounds = listAssets(SOUNDS_DIR, '.mp3', '/sounds');

  if (images.length === 0 || sounds.length === 0) {
    throw new Error('Challenge assets are missing.');
  }

  return { images, sounds };
}

function pickRandom(items, rng) {
  const index = Math.floor(rng() * items.length);
  return items[Math.min(index, items.length - 1)];
}

function createSpawnResponse(assets, rng) {
  const image = pickRandom(assets.images, rng);
  const sound = pickRandom(assets.sounds, rng);

  return {
    type: 'spawned',
    image,
    sound
  };
}

function sendJson(ws, payload) {
  if (ws.readyState !== WebSocket.OPEN) {
    return;
  }

  ws.send(JSON.stringify(payload));
}

function parseSpawnMessage(rawMessage) {
  let payload;

  try {
    payload = JSON.parse(rawMessage.toString('utf8'));
  } catch {
    return null;
  }

  if (
    !payload ||
    Array.isArray(payload) ||
    typeof payload !== 'object' ||
    payload.type !== 'spawn' ||
    Object.keys(payload).length !== 1
  ) {
    return null;
  }

  return payload;
}

function isInsideDirectory(baseDirectory, targetPath) {
  const relative = path.relative(baseDirectory, targetPath);
  return relative && !relative.startsWith('..') && !path.isAbsolute(relative);
}

function resolveStaticPath(requestUrl) {
  const url = new URL(requestUrl, 'http://localhost');
  const pathname = decodeURIComponent(url.pathname);

  if (pathname === '/') {
    return path.join(PUBLIC_DIR, 'index.html');
  }

  const staticRoots = [
    { prefix: '/images/', directory: IMAGES_DIR },
    { prefix: '/sounds/', directory: SOUNDS_DIR }
  ];

  for (const root of staticRoots) {
    if (!pathname.startsWith(root.prefix)) {
      continue;
    }

    const relativePath = pathname.slice(root.prefix.length);
    const targetPath = path.resolve(root.directory, relativePath);

    if (isInsideDirectory(root.directory, targetPath)) {
      return targetPath;
    }
  }

  return null;
}

function serveStatic(request, response) {
  let targetPath;

  try {
    targetPath = resolveStaticPath(request.url);
  } catch {
    response.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end('Bad Request');
    return;
  }

  if (!targetPath) {
    response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end('Not Found');
    return;
  }

  fs.stat(targetPath, (statError, stats) => {
    if (statError || !stats.isFile()) {
      response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      response.end('Not Found');
      return;
    }

    const contentType = CONTENT_TYPES[path.extname(targetPath).toLowerCase()] || 'application/octet-stream';
    response.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-store'
    });
    fs.createReadStream(targetPath).pipe(response);
  });
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function createConnectionState() {
  return {
    locked: false,
    nextSpawnId: 1,
    pendingBeforeLock: 0,
    raceWon: false
  };
}

function createRaceConfig(options = {}) {
  return {
    raceThreshold: options.raceThreshold || DEFAULT_RACE_THRESHOLD,
    preLockDelayMs: options.preLockDelayMs ?? DEFAULT_PRELOCK_DELAY_MS,
    spawnDelayMs: options.spawnDelayMs ?? DEFAULT_SPAWN_DELAY_MS
  };
}

async function handleSpawn(ws, state, assets, rng, flag, raceConfig) {
  if (state.locked) {
    sendJson(ws, {
      type: 'error',
      message: 'spawn already running'
    });
    return;
  }

  const spawnId = state.nextSpawnId++;
  state.pendingBeforeLock += 1;
  const contenders = state.pendingBeforeLock;

  await sleep(raceConfig.preLockDelayMs);
  state.locked = true;

  try {
    await sleep(raceConfig.spawnDelayMs);

    const response = createSpawnResponse(assets, rng);
    response.spawnId = spawnId;

    if (!state.raceWon && contenders >= raceConfig.raceThreshold) {
      state.raceWon = true;
      response.race = 'won';
      response.flag = flag;
    }

    sendJson(ws, response);
  } finally {
    state.pendingBeforeLock = Math.max(0, state.pendingBeforeLock - 1);

    if (state.pendingBeforeLock === 0) {
      state.locked = false;
    }
  }
}

function createServer(options = {}) {
  const assets = options.assets || loadAssets();
  const flag = options.flag || process.env.FLAG || DEFAULT_FLAG;
  const rng = options.rng || Math.random;
  const raceConfig = createRaceConfig(options);
  const server = http.createServer(serveStatic);
  const wss = new WebSocketServer({ server });

  wss.on('connection', (ws) => {
    const state = createConnectionState();

    ws.on('message', (message) => {
      const payload = parseSpawnMessage(message);

      if (!payload) {
        sendJson(ws, {
          type: 'error',
          message: 'invalid request'
        });
        return;
      }

      handleSpawn(ws, state, assets, rng, flag, raceConfig).catch(() => {
        sendJson(ws, {
          type: 'error',
          message: 'spawn failed'
        });
      });
    });
  });

  return { server, wss, assets };
}

if (require.main === module) {
  const { server } = createServer();

  server.listen(DEFAULT_PORT, () => {
    console.log(`Spawn Race challenge listening on http://localhost:${DEFAULT_PORT}`);
  });
}

module.exports = {
  DEFAULT_FLAG,
  DEFAULT_PRELOCK_DELAY_MS,
  DEFAULT_RACE_THRESHOLD,
  DEFAULT_SPAWN_DELAY_MS,
  createConnectionState,
  createRaceConfig,
  createServer,
  createSpawnResponse,
  handleSpawn,
  loadAssets,
  parseSpawnMessage,
  resolveStaticPath
};
