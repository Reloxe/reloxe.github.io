// Decentralized P2P WebRTC Configuration
// Stores signaling servers and STUN servers for NAT traversal.

const P2P_CONFIG = {
  // Pool of public PeerJS signaling servers
  // Only add servers you have verified are actually running PeerJS signaling
  signalingServers: [
    { host: '0.peerjs.com', port: 443, secure: true, path: '/' }
    // Add your own PeerJS servers here:
    // { host: 'your-peerjs-server.com', port: 443, secure: true, path: '/' }
  ],

  // Pool of free/public STUN servers (like Torrent track lists)
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

  // Timeout (ms) to wait for a signaling server before trying the next one
  serverTimeout: 8000
};

// Generates PeerJS initialization options for a specific server index
function getPeerOptions(serverIndex) {
  const index = parseInt(serverIndex, 10) || 0;
  const server = P2P_CONFIG.signalingServers[index % P2P_CONFIG.signalingServers.length];
  return {
    host: server.host,
    port: server.port,
    secure: server.secure,
    path: server.path || '/',
    config: {
      iceServers: P2P_CONFIG.iceServers
    },
    debug: 1 // Only log errors
  };
}

// Tries to connect a Peer to servers in the pool sequentially.
// Returns a Promise that resolves with { peer, serverIndex } on success,
// or rejects if ALL servers fail.
function tryConnectPeer(peerId, startIndex) {
  const totalServers = P2P_CONFIG.signalingServers.length;
  let attemptIndex = parseInt(startIndex, 10) || 0;

  function attemptServer(index, attemptsLeft) {
    return new Promise((resolve, reject) => {
      if (attemptsLeft <= 0) {
        reject(new Error("All signaling servers failed."));
        return;
      }

      const srvIdx = index % totalServers;
      const options = getPeerOptions(srvIdx);
      const server = P2P_CONFIG.signalingServers[srvIdx];
      console.log("Trying signaling server: " + server.host + " (index " + srvIdx + ")");

      const testPeer = new Peer(peerId, options);
      let settled = false;

      // Timeout: if no response in X seconds, try the next server
      const timeout = setTimeout(() => {
        if (!settled) {
          settled = true;
          console.warn("Server " + server.host + " timed out. Trying next...");
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
        // unavailable-id is NOT a server failure — it means the server works but ID is taken
        if (err.type === 'unavailable-id') {
          settled = true;
          clearTimeout(timeout);
          testPeer.destroy();
          // Resolve with a special flag so caller knows to go Guest mode on THIS server
          resolve({ peer: null, serverIndex: srvIdx, unavailableId: true });
        } else {
          // Server-level failure — try next
          settled = true;
          clearTimeout(timeout);
          console.warn("Server " + server.host + " error: " + err.message + ". Trying next...");
          testPeer.destroy();
          attemptServer(index + 1, attemptsLeft - 1).then(resolve).catch(reject);
        }
      });
    });
  }

  return attemptServer(attemptIndex, totalServers);
}

// Generate a random 256-bit key in hex format (64 characters)
function generateHexKey() {
  const bytes = new Uint8Array(32);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Import key for AES-GCM encryption/decryption
async function importKey(hexKey) {
  const rawKey = new Uint8Array(hexKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  return window.crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

// Helper to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Helper to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

// Encrypts plaintext string using AES-GCM and hexKey
async function encryptData(plaintext, hexKey) {
  try {
    const key = await importKey(hexKey);
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12-byte IV for AES-GCM
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encoded
    );
    const ivBase64 = arrayBufferToBase64(iv);
    const ciphertextBase64 = arrayBufferToBase64(ciphertextBuffer);
    return JSON.stringify({ iv: ivBase64, ct: ciphertextBase64 });
  } catch (e) {
    console.error("Encryption failed:", e);
    return null;
  }
}

// Decrypts encryptedJson string using AES-GCM and hexKey
async function decryptData(encryptedJson, hexKey) {
  try {
    const payload = JSON.parse(encryptedJson);
    if (!payload.iv || !payload.ct) return null;
    const key = await importKey(hexKey);
    const iv = new Uint8Array(base64ToArrayBuffer(payload.iv));
    const ciphertext = base64ToArrayBuffer(payload.ct);
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      ciphertext
    );
    return new TextDecoder().decode(decryptedBuffer);
  } catch (e) {
    console.error("Decryption failed:", e);
    return "[Şifre Çözme Başarısız: Geçersiz anahtar veya bozuk veri]";
  }
}

// Helper to extract the 64-character hex encryption key from the URL hash
function getEncryptionKey() {
  const hash = document.location.hash;
  if (!hash) return null;
  const match = hash.match(/key=([a-f0-9]{64})/i);
  return match ? match[1] : null;
}

