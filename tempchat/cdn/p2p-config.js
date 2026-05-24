const P2P_CONFIG = {
  signalingServers: [
    { host: '0.peerjs.com', port: 443, secure: true, path: '/' }
  ],
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' },
    { urls: 'stun:stun3.l.google.com:19302' },
    { urls: 'stun:stun4.l.google.com:19302' },
    { urls: 'stun:stun.ekiga.net' },
    { urls: 'stun:stun.ideasip.com' },
    { urls: 'stun:stun.schlund.de' }
  ],
  serverTimeout: 8000
};

function getPeerOptions(serverIndex) {
  const index = parseInt(serverIndex, 10) || 0;
  const server = P2P_CONFIG.signalingServers[index % P2P_CONFIG.signalingServers.length];
  return {
    host: server.host,
    port: server.port,
    secure: server.secure,
    path: server.path || '/',
    config: { iceServers: P2P_CONFIG.iceServers },
    debug: 1
  };
}

function tryConnectPeer(peerId, startIndex) {
  const totalServers = P2P_CONFIG.signalingServers.length;

  function attemptServer(index, attemptsLeft) {
    return new Promise((resolve, reject) => {
      if (attemptsLeft <= 0) {
        reject(new Error("All signaling servers failed."));
        return;
      }

      const srvIdx = index % totalServers;
      const options = getPeerOptions(srvIdx);
      const server = P2P_CONFIG.signalingServers[srvIdx];
      const testPeer = new Peer(peerId, options);
      let settled = false;

      const timeout = setTimeout(() => {
        if (!settled) {
          settled = true;
          testPeer.destroy();
          attemptServer(index + 1, attemptsLeft - 1).then(resolve).catch(reject);
        }
      }, P2P_CONFIG.serverTimeout);

      testPeer.on('open', (id) => {
        if (!settled) {
          settled = true;
          clearTimeout(timeout);
          resolve({ peer: testPeer, serverIndex: srvIdx });
        }
      });

      testPeer.on('error', (err) => {
        if (settled) return;
        if (err.type === 'unavailable-id') {
          settled = true;
          clearTimeout(timeout);
          testPeer.destroy();
          resolve({ peer: null, serverIndex: srvIdx, unavailableId: true });
        } else {
          settled = true;
          clearTimeout(timeout);
          testPeer.destroy();
          attemptServer(index + 1, attemptsLeft - 1).then(resolve).catch(reject);
        }
      });
    });
  }

  return attemptServer(parseInt(startIndex, 10) || 0, totalServers);
}

function generateHexKey() {
  const bytes = new Uint8Array(32);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function importKey(hexKey) {
  const rawKey = new Uint8Array(hexKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  return window.crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary_string = window.atob(base64);
  const bytes = new Uint8Array(binary_string.length);
  for (let i = 0; i < binary_string.length; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

async function encryptData(plaintext, hexKey) {
  try {
    const key = await importKey(hexKey);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertextBuffer = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, encoded);
    return JSON.stringify({ iv: arrayBufferToBase64(iv), ct: arrayBufferToBase64(ciphertextBuffer) });
  } catch (e) {
    return null;
  }
}

async function decryptData(encryptedJson, hexKey) {
  try {
    const payload = JSON.parse(encryptedJson);
    if (!payload.iv || !payload.ct) return null;
    const key = await importKey(hexKey);
    const iv = new Uint8Array(base64ToArrayBuffer(payload.iv));
    const ciphertext = base64ToArrayBuffer(payload.ct);
    const decryptedBuffer = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ciphertext);
    return new TextDecoder().decode(decryptedBuffer);
  } catch (e) {
    return "[Decryption Failed]";
  }
}

function getEncryptionKey() {
  const hash = document.location.hash;
  if (!hash) return null;
  const match = hash.match(/key=([a-f0-9]{64})/i);
  return match ? match[1] : null;
}
