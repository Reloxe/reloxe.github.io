// Decentralized P2P WebRTC Configuration
// Stores signaling servers and STUN servers for NAT traversal.

const P2P_CONFIG = {
  // Pool of public PeerJS signaling servers
  signalingServers: [
    { host: '0.peerjs.com', port: 443, secure: true, path: '/' },
    { host: 'peerjs.com', port: 443, secure: true, path: '/' }
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
  ]
};

// Generates PeerJS initialization options based on server pool index
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

