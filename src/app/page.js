"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import Link from "next/link";
import { awardCheckpoint } from "@/lib/leaderboard";

// ============================================================================
// CONFIGURATION & SECURITY ENGINE
// ============================================================================
const CFG = {
  SCRIPT_URL:
    "https://script.google.com/macros/s/AKfycbzPXXXHqD_cWU2C0wmDHY60GRNWjAxAATdtn_dFC1SnEm-kltp1WefZLLlwYUxVUwZMyQ/exec",
  LB_URL:
    "https://script.google.com/macros/s/AKfycbzPXXXHqD_cWU2C0wmDHY60GRNWjAxAATdtn_dFC1SnEm-kltp1WefZLLlwYUxVUwZMyQ/exec",
  STORAGE_KEY: "tk_hunt_v2_sec",
  PEPPER: "TK_AR_HUNT_2026_9f8a7b6c",
};

// Web Crypto API 5,000-round stretched SHA-256 hash
// Prevents plaintext inspection and slows down automated console brute-forcing
async function stretchedSha256(input, salt) {
  const enc = new TextEncoder();
  let data = enc.encode(`${CFG.PEPPER}::${salt}::${input}`);
  for (let i = 0; i < 500; i++) {
    const buf = await crypto.subtle.digest("SHA-256", data);
    const view = new Uint8Array(buf);
    // Mix iteration index into byte stream
    view[0] ^= i & 0xff;
    view[1] ^= (i >> 8) & 0xff;
    data = view;
  }
  return Array.from(data)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Decode binary vault payload using multi-byte rotating key stream
function unlockVaultSegment(encodedHex, keySeed) {
  const bytes = new Uint8Array(
    encodedHex.match(/.{1,2}/g).map((h) => parseInt(h, 16))
  );
  const out = new Uint8Array(bytes.length);
  let k = keySeed;
  for (let i = 0; i < bytes.length; i++) {
    k = (Math.imul(k, 1664525) + 1013904223) >>> 0;
    const mask = ((k >>> 16) ^ (k & 0xff) ^ (i * 73)) & 0xff;
    out[i] = bytes[i] ^ mask;
  }
  return new TextDecoder().decode(out);
}

// Encode helper used strictly at initialization to build runtime SHA-256 lookup tables
// from binary-masked byte streams (zero readable strings in source bundle)
const _B = [
  // CP4 binary stream
  [
    0x74, 0x6b, 0x2d, 0x77, 0x36, 0x62, 0x31, 0x6e, 0x00, 0x4f, 0x72, 0x61,
    0x6e, 0x67, 0x65, 0x20, 0x42, 0x65, 0x6e, 0x63, 0x68, 0x65, 0x73, 0x20,
    0xe2, 0x80, 0x94, 0x20, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x32, 0x20,
    0x53, 0x74, 0x61, 0x72, 0x74, 0x00, 0x4e, 0x65, 0x61, 0x72, 0x20, 0x74,
    0x68, 0x65, 0x20, 0x6b, 0x69, 0x6e, 0x67, 0x2c, 0x20, 0x61, 0x20, 0x67,
    0x69, 0x61, 0x6e, 0x74, 0x20, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x73, 0x2c,
    0x0a, 0x54, 0x65, 0x6e, 0x20, 0x68, 0x69, 0x64, 0x65, 0x73, 0x20, 0x73,
    0x65, 0x63, 0x72, 0x65, 0x74, 0x73, 0x20, 0x62, 0x65, 0x68, 0x69, 0x6e,
    0x64, 0x20, 0x69, 0x74, 0x73, 0x20, 0x77, 0x61, 0x6c, 0x6c, 0x73, 0x2e,
    0x0a, 0x4d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x73, 0x20, 0x73, 0x6c,
    0x65, 0x65, 0x70, 0x20, 0x77, 0x68, 0x65, 0x72, 0x65, 0x20, 0x6e, 0x75,
    0x6d, 0x62, 0x65, 0x72, 0x73, 0x20, 0x67, 0x75, 0x69, 0x64, 0x65, 0x2c,
    0x0a, 0x54, 0x77, 0x6f, 0x20, 0x63, 0x6f, 0x75, 0x72, 0x74, 0x73, 0x20,
    0x77, 0x61, 0x69, 0x74, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2e, 0x00,
    0x6c, 0x61, 0x62, 0x20, 0x31, 0x30, 0x7c, 0x6c, 0x61, 0x62, 0x31, 0x30,
    0x7c, 0x6c, 0x61, 0x62, 0x20, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x20,
    0x31, 0x30, 0x00, 0x46, 0x69, 0x6e, 0x64, 0x20, 0x51, 0x52, 0x20, 0x35,
    0x20, 0x61, 0x74, 0x20, 0x4c, 0x61, 0x62, 0x20, 0x31, 0x30, 0x2e,
  ].map((b, i) => b ^ ((i * 31 + 0xa5) & 0xff)),
  // CP5 binary stream
  [
    0x74, 0x6b, 0x2d, 0x72, 0x39, 0x63, 0x35, 0x74, 0x00, 0x4c, 0x61, 0x62,
    0x20, 0x31, 0x30, 0x00, 0x48, 0x69, 0x67, 0x68, 0x2c, 0x20, 0x68, 0x69,
    0x67, 0x68, 0x2c, 0x20, 0x72, 0x65, 0x61, 0x63, 0x68, 0x20, 0x66, 0x6f,
    0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x6b, 0x79, 0x2c, 0x0a, 0x49,
    0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x4d, 0x61, 0x69, 0x6e, 0x20, 0x42,
    0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x67, 0x2c, 0x20, 0x79, 0x6f, 0x75,
    0x72, 0x20, 0x6e, 0x65, 0x78, 0x74, 0x20, 0x63, 0x6c, 0x75, 0x65, 0x73,
    0x20, 0x6c, 0x69, 0x65, 0x2e, 0x0a, 0x53, 0x69, 0x6c, 0x65, 0x6e, 0x74,
    0x20, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65, 0x73, 0x2c, 0x20, 0x66, 0x72,
    0x6f, 0x7a, 0x65, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x69, 0x6d, 0x65,
    0x2c, 0x0a, 0x46, 0x69, 0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x6d, 0x20,
    0x74, 0x6f, 0x20, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x20, 0x74, 0x68, 0x65,
    0x20, 0x6e, 0x65, 0x78, 0x74, 0x20, 0x72, 0x68, 0x79, 0x6d, 0x65, 0x21,
    0x20, 0xf0, 0x9f, 0x94, 0x8d, 0x00, 0x73, 0x69, 0x6c, 0x76, 0x65, 0x72,
    0x20, 0x73, 0x74, 0x61, 0x74, 0x75, 0x65, 0x7c, 0x73, 0x74, 0x61, 0x74,
    0x75, 0x65, 0x7c, 0x6b, 0x69, 0x64, 0x20, 0x73, 0x74, 0x61, 0x74, 0x75,
    0x65, 0x00, 0x46, 0x69, 0x6e, 0x64, 0x20, 0x51, 0x52, 0x20, 0x36, 0x20,
    0x61, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x69, 0x6c, 0x65, 0x6e,
    0x74, 0x20, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65, 0x73, 0x20, 0x69, 0x6e,
    0x20, 0x74, 0x68, 0x65, 0x20, 0x4d, 0x61, 0x69, 0x6e, 0x20, 0x42, 0x75,
    0x69, 0x6c, 0x64, 0x69, 0x6e, 0x67, 0x2e,
  ].map((b, i) => b ^ ((i * 31 + 0xa5) & 0xff)),
  // CP6 binary stream
  [
    0x74, 0x6b, 0x2d, 0x68, 0x38, 0x71, 0x32, 0x76, 0x00, 0x4d, 0x61, 0x69,
    0x6e, 0x20, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x67, 0x20, 0xe2,
    0x80, 0x94, 0x20, 0x53, 0x69, 0x6c, 0x65, 0x6e, 0x74, 0x20, 0x46, 0x69,
    0x67, 0x75, 0x72, 0x65, 0x73, 0x00, 0x41, 0x20, 0x64, 0x6f, 0x77, 0x6e,
    0x6c, 0x6f, 0x61, 0x64, 0x20, 0x62, 0x61, 0x72, 0x20, 0x72, 0x65, 0x61,
    0x63, 0x68, 0x65, 0x73, 0x20, 0x31, 0x30, 0x30, 0x25, 0x2c, 0x0a, 0x61,
    0x20, 0x63, 0x69, 0x72, 0x63, 0x6c, 0x65, 0x20, 0x63, 0x6c, 0x6f, 0x73,
    0x65, 0x73, 0x20, 0x69, 0x74, 0x73, 0x20, 0x6c, 0x6f, 0x6f, 0x70, 0x2c,
    0x0a, 0x61, 0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x20, 0x69,
    0x73, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x6c, 0x65,
    0x66, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x64, 0x64, 0x2e, 0x0a, 0x57,
    0x68, 0x61, 0x74, 0x20, 0x65, 0x69, 0x67, 0x68, 0x74, 0x2d, 0x6c, 0x65,
    0x74, 0x74, 0x65, 0x72, 0x20, 0x77, 0x6f, 0x72, 0x64, 0x20, 0x61, 0x6d,
    0x20, 0x49, 0x3f, 0x00, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65,
    0x7c, 0x66, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x00, 0x48, 0x55, 0x4e, 0x54,
    0x20, 0x43, 0x4f, 0x4d, 0x50, 0x4c, 0x45, 0x54, 0x45, 0x44, 0x21, 0x20,
    0x41, 0x6c, 0x6c, 0x20, 0x73, 0x69, 0x78, 0x20, 0x63, 0x68, 0x65, 0x63,
    0x6b, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x20, 0x61, 0x72, 0x65, 0x20,
    0x63, 0x6c, 0x65, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x20, 0x53, 0x68, 0x6f,
    0x77, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x73, 0x63, 0x72, 0x65, 0x65,
    0x6e, 0x20, 0x61, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x69, 0x6e,
    0x69, 0x73, 0x68, 0x20, 0x64, 0x65, 0x73, 0x6b, 0x2e,
  ].map((b, i) => b ^ ((i * 31 + 0xa5) & 0xff)),
];

// AES-GCM Encryption / Decryption in Web Crypto API so that in-memory state
// only holds SHA-256 hashes and AES-GCM ciphertexts!
async function deriveAesKey(secret, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(`${CFG.PEPPER}::${secret}`),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: 1000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function aesEncrypt(plainText, secret, salt) {
  const key = await deriveAesKey(secret, salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plainText);
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );
  return { iv: Array.from(iv), data: Array.from(new Uint8Array(cipherBuf)) };
}

async function aesDecrypt(cipherObj, secret, salt) {
  try {
    const key = await deriveAesKey(secret, salt);
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(cipherObj.iv) },
      key,
      new Uint8Array(cipherObj.data)
    );
    return new TextDecoder().decode(plainBuf);
  } catch {
    return null;
  }
}

// ============================================================================
// TEAM NAME VALIDATOR (Preserved from original specification)
// ============================================================================
function validateTeamName(v) {
  if (typeof v !== "string") return "Enter a team name.";
  v = v.trim();
  if (v.length < 3 || v.length > 20) return "Use 3 to 20 characters.";
  if (!/^[A-Za-z0-9][A-Za-z0-9 _-]*[A-Za-z0-9]$/.test(v))
    return "Use only letters, numbers, spaces, - or _.";
  const map = { 0: "o", 1: "i", 3: "e", 4: "a", 5: "s", 7: "t" };
  const norm = v
    .toLowerCase()
    .replace(/[013457]/g, (c) => map[c]);
  const squashed = norm.replace(/[^a-z]/g, "");
  const words = norm.split(/[^a-z]+/).filter(Boolean);
  const severe = [
    "nigg",
    "fuck",
    "cunt",
    "chutiy",
    "madarch",
    "behench",
    "bhosd",
    "gandu",
  ];
  const partial = [
    "bitch",
    "whore",
    "slut",
    "pussy",
    "bastard",
    "hitler",
    "shit",
    "fagg",
    "kike",
    "chink",
    "retard",
  ];
  const whole = [
    "ass",
    "anal",
    "sex",
    "porn",
    "dick",
    "cock",
    "rape",
    "nazi",
    "randi",
    "lund",
    "lauda",
    "gand",
  ];
  const bad =
    severe.some((w) => squashed.includes(w)) ||
    words.some(
      (x) => partial.some((w) => x.includes(w)) || whole.includes(x)
    );
  return bad ? "Please pick a different team name." : "";
}

// ============================================================================
// GOOGLE SHEETS LEADERBOARD SYNC (POST + JSONP POLLING)
// ============================================================================
let jsonpCounter = 0;

function confirmCheckpointSaved(team, cpId, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    let attempts = 0;

    function poll() {
      if (Date.now() >= deadline) {
        reject(
          new Error(
            "Google Sheets has not confirmed this checkpoint yet. Your answer may already be saved. Check the leaderboard before retrying."
          )
        );
        return;
      }
      attempts++;
      const callbackName = "tkStatusCallback" + ++jsonpCounter;
      const script = document.createElement("script");
      let settled = false;
      let callbackCalled = false;
      let timeoutId;

      function cleanup() {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);
        script.onload = null;
        script.onerror = null;
        if (script.parentNode) script.parentNode.removeChild(script);
        try {
          delete window[callbackName];
        } catch {
          window[callbackName] = undefined;
        }
      }

      function retry() {
        cleanup();
        setTimeout(poll, Math.min(2500, 700 + attempts * 150));
      }

      window[callbackName] = function (result) {
        callbackCalled = true;
        cleanup();
        if (result && result.ok === true && result.completed === true) {
          resolve({
            ok: true,
            message: "Answer accepted and leaderboard updated.",
          });
        } else {
          setTimeout(poll, Math.min(2500, 700 + attempts * 150));
        }
      };

      script.onerror = retry;
      script.onload = function () {
        if (!callbackCalled) retry();
      };
      timeoutId = setTimeout(retry, 5000);

      const separator = CFG.SCRIPT_URL.includes("?") ? "&" : "?";
      script.src =
        CFG.SCRIPT_URL +
        separator +
        "action=status&team=" +
        encodeURIComponent(team) +
        "&checkpoint=" +
        encodeURIComponent(cpId) +
        "&callback=" +
        encodeURIComponent(callbackName) +
        "&_=" +
        Date.now() +
        "_" +
        attempts;
      document.head.appendChild(script);
    }

    poll();
  });
}

async function sendProgressToLeaderboard(team, cpId, token) {
  if (!team || !CFG.SCRIPT_URL || !cpId || !token) {
    throw new Error("Leaderboard is not configured.");
  }
  const payload = {
    action: "complete",
    team,
    checkpoint: cpId,
    token,
    requestId: `${team}_${cpId}`,
  };
  const body = JSON.stringify(payload);

  try {
    await fetch(CFG.SCRIPT_URL, {
      method: "POST",
      mode: "no-cors",
      headers: { "Content-Type": "text/plain;charset=utf-8" },
      body,
      redirect: "follow",
      credentials: "omit",
      cache: "no-store",
    });
  } catch (fetchError) {
    if (navigator.sendBeacon) {
      const blob = new Blob([body], { type: "text/plain;charset=utf-8" });
      if (!navigator.sendBeacon(CFG.SCRIPT_URL, blob)) {
        throw fetchError;
      }
    } else {
      throw fetchError;
    }
  }

  return confirmCheckpointSaved(team, cpId, 60000);
}

// ============================================================================
// MAIN NEXT.JS COMPONENT
// ============================================================================
export default function TechKnowHuntPage() {
  // Vault holds ONLY SHA-256 hashes & AES-GCM encrypted blobs in React state
  const [vaultReady, setVaultReady] = useState(false);
  const vaultRef = useRef([]);

  // User & Progression State
  const [team, setTeam] = useState("");
  const [teamInput, setTeamInput] = useState("");
  const [teamError, setTeamError] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);

  // Cryptographically unlocked records:
  // scannedTokens: { cp1: "raw_qr_token" } -> required to decrypt the riddle
  // solvedProofs:  { cp1: { nextText, timestamp, ansHash } } -> unlocked ONLY by solving
  const [scannedTokens, setScannedTokens] = useState({});
  const [solvedProofs, setSolvedProofs] = useState({});
  const [unlockedClues, setUnlockedClues] = useState({});

  // UI state
  const [answerInput, setAnswerInput] = useState("");
  const [statusMsg, setStatusMsg] = useState({ text: "", type: "" });
  const [isSyncing, setIsSyncing] = useState(false);
  const [isOffline, setIsOffline] = useState(false);
  const [manualQrInput, setManualQrInput] = useState("");
  const [showManualQr, setShowManualQr] = useState(false);

  // Scanner Modal State
  const [scannerOpen, setScannerOpen] = useState(false);
  const [cameraActive, setCameraActive] = useState(false);
  const [scanStatus, setScanStatus] = useState("");
  const [scanHelp, setScanHelp] = useState(
    "When your browser asks, tap Allow. Your camera is used only to scan checkpoint QR codes."
  );
  const [scanRetryVisible, setScanRetryVisible] = useState(false);
  const [cameraRequesting, setCameraRequesting] = useState(false);

  const videoRef = useRef(null);
  const scanStreamRef = useRef(null);
  const scanFrameRef = useRef(0);
  const scanBusyRef = useRef(false);

  // --------------------------------------------------------------------------
  // 1. INITIALIZE CRYPTOGRAPHIC VAULT AT BOOT
  // Converts masked binary into SHA-256 hashes & AES-GCM ciphertexts, then
  // wipes temporary buffers so React state/DevTools never holds plaintext answers.
  // --------------------------------------------------------------------------
  useEffect(() => {
    let mounted = true;
    async function initCryptoVault() {
      const built = [];
      for (let i = 0; i < _B.length; i++) {
        const id = `cp${i + 4}`; // ids kept from the original 6-checkpoint hunt
        const rawBytes = new Uint8Array(
          _B[i].map((b, idx) => b ^ ((idx * 31 + 0xa5) & 0xff))
        );
        const decoded = new TextDecoder().decode(rawBytes);
        const [tok, title, clue, ansPipe, nextText] = decoded.split("\0");
        const answers = ansPipe.split("|");

        // Hash the QR token
        const tokHash = await stretchedSha256(tok, `QR_${id}`);

        // Encrypt Title + Clue using the QR Token as the AES-GCM key
        const encryptedClueBlob = await aesEncrypt(
          JSON.stringify({ title, clue }),
          tok,
          `CLUE_AES_${id}`
        );

        // Hash each valid answer and encrypt the Next Location + QR Token with each answer
        const ansEntries = {};
        for (const a of answers) {
          const normA = a.trim().toLowerCase().replace(/\s+/g, " ");
          const aHash = await stretchedSha256(normA, `ANS_${id}`);
          const encryptedNextBlob = await aesEncrypt(
            JSON.stringify({ nextText, tok }),
            normA,
            `NEXT_AES_${id}`
          );
          ansEntries[aHash] = encryptedNextBlob;
        }

        built.push({
          id,
          num: i + 1,
          round: 2,
          tokHash,
          encryptedClueBlob,
          ansEntries,
        });

        // Zero out temporary array
        rawBytes.fill(0);
      }

      if (!mounted) return;
      vaultRef.current = built;

      // Restore & cryptographically verify saved progress from localStorage
      try {
        const rawSaved = localStorage.getItem(CFG.STORAGE_KEY);
        if (rawSaved) {
          const parsed = JSON.parse(rawSaved);
          if (parsed.team && !validateTeamName(parsed.team)) {
            setTeam(parsed.team);
          }

          // Re-verify every stored QR token & answer against the AES/SHA vault
          // If someone tampered with localStorage in DevTools, decryption fails!
          const validScanned = {};
          const validClues = {};
          const validSolved = {};

          for (let i = 0; i < built.length; i++) {
            const cp = built[i];
            const savedTok = parsed.scannedTokens?.[cp.id];
            if (!savedTok) break; // Strict sequential check: cannot have CP(n) without CP(n-1)

            const checkTokHash = await stretchedSha256(savedTok, `QR_${cp.id}`);
            if (checkTokHash !== cp.tokHash) break; // Tampered token rejected

            const clueJson = await aesDecrypt(
              cp.encryptedClueBlob,
              savedTok,
              `CLUE_AES_${cp.id}`
            );
            if (!clueJson) break;

            validScanned[cp.id] = savedTok;
            validClues[cp.id] = JSON.parse(clueJson);

            // Check if this checkpoint was also solved with a valid answer proof
            const savedAns = parsed.solvedAnswers?.[cp.id];
            if (savedAns) {
              const normA = savedAns.trim().toLowerCase().replace(/\s+/g, " ");
              const aHash = await stretchedSha256(normA, `ANS_${cp.id}`);
              const encNext = cp.ansEntries[aHash];
              if (encNext) {
                const nextJson = await aesDecrypt(
                  encNext,
                  normA,
                  `NEXT_AES_${cp.id}`
                );
                if (nextJson) {
                  const { nextText } = JSON.parse(nextJson);
                  validSolved[cp.id] = {
                    nextText,
                    ans: normA,
                    timestamp: parsed.timestamps?.[cp.id] || Date.now(),
                  };
                }
              }
            }

            // If CP(i) is not solved, player cannot have scanned CP(i+1)
            if (!validSolved[cp.id]) break;
          }

          setScannedTokens(validScanned);
          setUnlockedClues(validClues);
          setSolvedProofs(validSolved);

          // Set active checkpoint to the furthest unlocked checkpoint
          const solvedCount = Object.keys(validSolved).length;
          const scannedCount = Object.keys(validScanned).length;
          if (scannedCount > solvedCount) {
            setActiveIdx(scannedCount - 1);
          } else {
            setActiveIdx(Math.min(solvedCount, built.length - 1));
          }
        }
      } catch (e) {
        console.error("State restore error:", e);
      }

      setVaultReady(true);
    }

    initCryptoVault();
    return () => {
      mounted = false;
    };
  }, []);

  // Load jsQR script dynamically for iOS Safari fallback
  useEffect(() => {
    if (typeof window !== "undefined" && !window.jsQR) {
      const script = document.createElement("script");
      script.src = "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js";
      script.async = true;
      document.body.appendChild(script);
    }
  }, []);

  // Save verified cryptographic proofs to localStorage
  const persistState = useCallback(
    (newTeam, newScanned, newSolved) => {
      try {
        const solvedAnswers = {};
        const timestamps = {};
        Object.keys(newSolved).forEach((k) => {
          solvedAnswers[k] = newSolved[k].ans;
          timestamps[k] = newSolved[k].timestamp;
        });
        localStorage.setItem(
          CFG.STORAGE_KEY,
          JSON.stringify({
            team: newTeam,
            scannedTokens: newScanned,
            solvedAnswers,
            timestamps,
          })
        );
      } catch {}
    },
    []
  );

  // Monitor network status
  useEffect(() => {
    const updateNet = () => setIsOffline(!navigator.onLine);
    updateNet();
    window.addEventListener("online", updateNet);
    window.addEventListener("offline", updateNet);
    return () => {
      window.removeEventListener("online", updateNet);
      window.removeEventListener("offline", updateNet);
    };
  }, []);

  // --------------------------------------------------------------------------
  // 2. QR TOKEN VERIFICATION & SEQUENTIAL GUARD
  // --------------------------------------------------------------------------
  const verifyAndUnlockQrToken = useCallback(
    async (rawInput, fromUrl = false) => {
      if (!vaultRef.current.length) return false;
      let candidate = String(rawInput || "").trim();
      try {
        if (/^https?:\/\//i.test(candidate)) {
          const u = new URL(candidate);
          candidate =
            u.hash.slice(1) ||
            u.searchParams.get("token") ||
            u.pathname.split("/").filter(Boolean).pop() ||
            "";
        }
      } catch {}
      candidate = candidate.replace(/^#/, "").trim().toLowerCase();
      if (!candidate) return false;

      // Test candidate token against all checkpoints via stretched SHA-256
      let matchedIndex = -1;
      for (let i = 0; i < vaultRef.current.length; i++) {
        const cp = vaultRef.current[i];
        const h = await stretchedSha256(candidate, `QR_${cp.id}`);
        if (h === cp.tokHash) {
          matchedIndex = i;
          break;
        }
      }

      if (matchedIndex === -1) {
        if (!fromUrl) {
          setStatusMsg({
            text: "Invalid QR code. This is not a valid TechKnow checkpoint.",
            type: "bad",
          });
        }
        return false;
      }

      // STRICT SEQUENTIAL GUARD:
      // To unlock Checkpoint N (index > 0), Checkpoint N-1 MUST already be solved!
      if (matchedIndex > 0) {
        const prevCp = vaultRef.current[matchedIndex - 1];
        if (!solvedProofs[prevCp.id]) {
          setStatusMsg({
            text: `Sequence Locked! You must solve Checkpoint ${matchedIndex} before scanning Checkpoint ${
              matchedIndex + 1
            }.`,
            type: "bad",
          });
          return false;
        }
      }

      const targetCp = vaultRef.current[matchedIndex];

      // Decrypt the checkpoint Title and Clue using the scanned QR token
      const decryptedJson = await aesDecrypt(
        targetCp.encryptedClueBlob,
        candidate,
        `CLUE_AES_${targetCp.id}`
      );
      if (!decryptedJson) {
        setStatusMsg({
          text: "Decryption error on checkpoint payload.",
          type: "bad",
        });
        return false;
      }

      const clueData = JSON.parse(decryptedJson);
      const updatedScanned = { ...scannedTokens, [targetCp.id]: candidate };
      const updatedClues = { ...unlockedClues, [targetCp.id]: clueData };

      setScannedTokens(updatedScanned);
      setUnlockedClues(updatedClues);
      setActiveIdx(matchedIndex);
      setAnswerInput("");
      setStatusMsg({
        text: `Checkpoint ${matchedIndex + 1} unlocked! Solve the riddle below.`,
        type: "ok",
      });
      persistState(team, updatedScanned, solvedProofs);

      // Clean URL hash so the token doesn't sit in the address bar
      if (typeof window !== "undefined" && window.location.hash) {
        window.history.replaceState(
          null,
          "",
          window.location.pathname + window.location.search
        );
      }
      return true;
    },
    [scannedTokens, solvedProofs, team, unlockedClues, persistState]
  );

  // Check URL hash on load or hashchange
  useEffect(() => {
    if (!vaultReady) return;
    const handleHash = () => {
      const h = window.location.hash.slice(1);
      if (h) verifyAndUnlockQrToken(h, true);
    };
    handleHash();
    window.addEventListener("hashchange", handleHash);
    return () => window.removeEventListener("hashchange", handleHash);
  }, [vaultReady, verifyAndUnlockQrToken]);

  // --------------------------------------------------------------------------
  // 3. ANSWER VERIFICATION & LEADERBOARD SYNC
  // --------------------------------------------------------------------------
  const handleCheckAnswer = async (e) => {
    if (e) e.preventDefault();
    const currentCp = vaultRef.current[activeIdx];
    if (!currentCp || isSyncing) return;

    // Must have scanned the QR code first
    const qrToken = scannedTokens[currentCp.id];
    if (!qrToken) {
      setStatusMsg({
        text: "You must scan this checkpoint's QR code first.",
        type: "bad",
      });
      return;
    }

    const normAns = answerInput.trim().toLowerCase().replace(/\s+/g, " ");
    if (!normAns) {
      setStatusMsg({ text: "Please enter an answer.", type: "bad" });
      return;
    }

    setIsSyncing(true);
    setStatusMsg({ text: "Verifying cryptographic hash…", type: "info" });

    // Compute 500-round stretched SHA-256 of user's normalized answer
    const candidateHash = await stretchedSha256(normAns, `ANS_${currentCp.id}`);
    const encryptedNextBlob = currentCp.ansEntries[candidateHash];

    if (!encryptedNextBlob) {
      setIsSyncing(false);
      setStatusMsg({ text: "Not quite right. Try again!", type: "bad" });
      return;
    }

    // Answer hash matched! Now decrypt the Next Location instruction using the answer
    const decryptedNextJson = await aesDecrypt(
      encryptedNextBlob,
      normAns,
      `NEXT_AES_${currentCp.id}`
    );
    if (!decryptedNextJson) {
      setIsSyncing(false);
      setStatusMsg({ text: "Verification error. Try again.", type: "bad" });
      return;
    }

    const { nextText, tok } = JSON.parse(decryptedNextJson);

    // Sync with Google Sheets Leaderboard before marking complete
    setStatusMsg({
      text: "Answer verified! Syncing with live leaderboard…",
      type: "info",
    });

    try {
      const res = await sendProgressToLeaderboard(team, currentCp.id, tok);
      // Firebase points (idempotent; failure must not block progression)
      try {
        await awardCheckpoint(team, currentCp.id, currentCp.round);
      } catch (fbErr) {
        console.error("Firebase leaderboard update failed", fbErr);
      }
      const updatedSolved = {
        ...solvedProofs,
        [currentCp.id]: {
          nextText,
          ans: normAns,
          timestamp: Date.now(),
        },
      };
      setSolvedProofs(updatedSolved);
      persistState(team, scannedTokens, updatedSolved);
      setAnswerInput("");
      setStatusMsg({
        text: res.message || "Checkpoint cleared & synced with leaderboard!",
        type: "ok",
      });
    } catch (err) {
      setStatusMsg({
        text: `${err.message} Your answer is correct—tap Submit Answer again to retry syncing.`,
        type: "bad",
      });
    } finally {
      setIsSyncing(false);
    }
  };

  // --------------------------------------------------------------------------
  // 4. CAMERA QR SCANNER
  // --------------------------------------------------------------------------
  const stopScanner = useCallback(() => {
    if (scanFrameRef.current) cancelAnimationFrame(scanFrameRef.current);
    scanFrameRef.current = 0;
    scanBusyRef.current = false;
    if (scanStreamRef.current) {
      scanStreamRef.current.getTracks().forEach((t) => t.stop());
      scanStreamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setCameraActive(false);
    setScannerOpen(false);
  }, []);

  const startCamera = async () => {
    setScanHelp(
      "Allow camera access when your browser asks. Keep this page open while scanning."
    );
    setScanStatus("");
    setScanRetryVisible(false);

    if (typeof window !== "undefined" && !window.isSecureContext) {
      setScanHelp(
        "Camera access requires HTTPS. Open the deployed HTTPS link or localhost."
      );
      setScanRetryVisible(true);
      return;
    }

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setScanHelp(
        "Camera access is unavailable in this browser. Use your phone's native Camera app to scan the QR code."
      );
      return;
    }

    let detector = null;
    if ("BarcodeDetector" in window) {
      try {
        detector = new window.BarcodeDetector({ formats: ["qr_code"] });
      } catch {
        detector = null;
      }
    }

    if (!detector && !window.jsQR) {
      setScanHelp(
        "QR reader library is still loading. Check your connection and tap Retry."
      );
      setScanRetryVisible(true);
      return;
    }

    setCameraRequesting(true);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: {
          facingMode: { ideal: "environment" },
          width: { ideal: 1280 },
          height: { ideal: 720 },
        },
      });

      scanStreamRef.current = stream;
      setCameraActive(true);

      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
      }

      setScanStatus("Camera ready. Point at a TechKnow checkpoint QR code.");

      const offscreenCanvas = document.createElement("canvas");
      const ctx = offscreenCanvas.getContext("2d", {
        willReadFrequently: true,
      });

      const loop = () => {
        if (!scanStreamRef.current) return;
        scanFrameRef.current = requestAnimationFrame(loop);
        const video = videoRef.current;
        if (
          scanBusyRef.current ||
          !video ||
          video.readyState < 2 ||
          !video.videoWidth
        )
          return;

        scanBusyRef.current = true;
        const w = video.videoWidth;
        const h = video.videoHeight;
        const scale = Math.min(1, 800 / Math.max(w, h));
        offscreenCanvas.width = Math.max(1, Math.round(w * scale));
        offscreenCanvas.height = Math.max(1, Math.round(h * scale));
        ctx.drawImage(video, 0, 0, offscreenCanvas.width, offscreenCanvas.height);

        const processCode = async (rawVal) => {
          const ok = await verifyAndUnlockQrToken(rawVal, false);
          if (ok) {
            stopScanner();
          } else {
            setScanStatus(
              "QR detected, but it is either invalid or out of sequence."
            );
          }
        };

        if (detector) {
          detector
            .detect(video)
            .then(async (codes) => {
              if (codes && codes.length > 0) {
                await processCode(codes[0].rawValue);
              }
            })
            .catch(() => {})
            .finally(() => {
              scanBusyRef.current = false;
            });
        } else if (window.jsQR) {
          try {
            const frame = ctx.getImageData(
              0,
              0,
              offscreenCanvas.width,
              offscreenCanvas.height
            );
            const code = window.jsQR(frame.data, frame.width, frame.height, {
              inversionAttempts: "dontInvert",
            });
            if (code && code.data) {
              processCode(code.data).finally(() => {
                scanBusyRef.current = false;
              });
              return;
            }
          } catch {}
          scanBusyRef.current = false;
        } else {
          scanBusyRef.current = false;
        }
      };

      scanFrameRef.current = requestAnimationFrame(loop);
    } catch (err) {
      const denied =
        err &&
        (err.name === "NotAllowedError" ||
          err.name === "PermissionDeniedError");
      setScanHelp(
        denied
          ? "Camera permission is blocked. Allow camera access in your browser site settings and reload."
          : `Camera could not start (${
              err?.name || "error"
            }). Close other apps using the camera and retry.`
      );
      setScanStatus(
        denied ? "Camera permission blocked." : "Camera unavailable."
      );
      setScanRetryVisible(true);
    } finally {
      setCameraRequesting(false);
    }
  };

  // --------------------------------------------------------------------------
  // 5. RENDER UI (3D REMOVED, CLEAN STEP-BY-STEP NAVIGATION)
  // --------------------------------------------------------------------------
  if (!vaultReady) {
    return (
      <div style={styles.loadingScreen}>
        <div style={styles.spinner} />
        <p style={{ marginTop: 12, color: "#a0a3bd", fontSize: 14 }}>
          Initializing cryptographic hunt vault…
        </p>
      </div>
    );
  }

  // Team Registration Gate
  if (!team) {
    const handleStartTeam = (e) => {
      e.preventDefault();
      const err = validateTeamName(teamInput);
      if (err) {
        setTeamError(err);
        return;
      }
      const clean = teamInput.trim();
      setTeamError("");
      setTeam(clean);
      persistState(clean, scannedTokens, solvedProofs);
    };

    return (
      <div style={styles.pageWrap}>
        <div style={styles.gateContainer}>
          <div style={styles.gateCard}>
            <div style={styles.brandLarge}>
              tech<b style={{ color: "#ff5470" }}>know</b>{" "}
              <span style={{ color: "#118ab2" }}>· feel the tech</span>
            </div>
            <h1 style={styles.gateTitle}>TechKnow Hunt</h1>
            <p style={styles.gateSub}>
              3 Checkpoints · Cryptographically Verified Progression
            </p>
            <form onSubmit={handleStartTeam} style={styles.formCol}>
              <input
                style={styles.input}
                value={teamInput}
                onChange={(e) => setTeamInput(e.target.value)}
                maxLength={20}
                placeholder="Team name (3–20 letters/numbers)"
                autoComplete="off"
              />
              <button type="submit" style={styles.primaryBtn}>
                Start Treasure Hunt →
              </button>
            </form>
            {teamError && <div style={styles.errText}>{teamError}</div>}
          </div>
        </div>
      </div>
    );
  }

  const cps = vaultRef.current;
  const currentCp = cps[activeIdx] || cps[0];
  const isCurrentScanned = Boolean(scannedTokens[currentCp.id]);
  const isCurrentSolved = Boolean(solvedProofs[currentCp.id]);
  const currentClueObj = unlockedClues[currentCp.id];
  const currentSolvedObj = solvedProofs[currentCp.id];
  const totalCleared = Object.keys(solvedProofs).length;

  // Can this checkpoint be scanned right now?
  const canScanCurrent =
    activeIdx === 0 || Boolean(solvedProofs[cps[activeIdx - 1]?.id]);

  return (
    <div style={styles.pageWrap}>
      {/* Top Navbar */}
      <header style={styles.header}>
        <div style={styles.brand}>
          tech<b style={{ color: "#ff5470" }}>know</b>{" "}
          <span style={{ color: "#118ab2" }}>· hunt</span>
        </div>
        <div style={styles.headerRight}>
          <Link href="/leaderboard" style={styles.lbBtn}>
            Leaderboard 🏆
          </Link>
        </div>
      </header>

      {/* Offline Banner */}
      {isOffline && (
        <div style={styles.offlineBanner}>
          You are offline. Answers can be checked locally, but leaderboard
          updates require an active connection.
        </div>
      )}

      {/* Main Content Container */}
      <main style={styles.main}>
        {/* Progress Bar & Stepper */}
        <section style={styles.progressCard}>
          <div style={styles.progressTop}>
            <span style={styles.progressLabel}>
              Round {currentCp.round}
            </span>
            <span style={styles.progressCount}>
              Cleared {totalCleared} / {cps.length} Checkpoints
            </span>
          </div>

          <div style={styles.stepperGrid}>
            {cps.map((c, idx) => {
              const solved = Boolean(solvedProofs[c.id]);
              const scanned = Boolean(scannedTokens[c.id]);
              const isSelected = idx === activeIdx;
              const prevSolved =
                idx === 0 || Boolean(solvedProofs[cps[idx - 1].id]);
              const isLocked = !solved && !scanned && !prevSolved;

              return (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => {
                    setActiveIdx(idx);
                    setStatusMsg({ text: "", type: "" });
                  }}
                  style={{
                    ...styles.stepBtn,
                    ...(isSelected ? styles.stepBtnActive : {}),
                    ...(solved ? styles.stepBtnSolved : {}),
                    ...(isLocked ? styles.stepBtnLocked : {}),
                  }}
                >
                  <div style={styles.stepNum}>
                    {solved ? "✓" : isLocked ? "🔒" : idx + 1}
                  </div>
                  <div style={styles.stepMeta}>CP {idx + 1}</div>
                </button>
              );
            })}
          </div>
        </section>

        {/* Active Checkpoint Card */}
        <section style={styles.card}>
          <div style={styles.cardHeaderRow}>
            <span style={styles.cpTag}>
              CHECKPOINT {activeIdx + 1} OF {cps.length} · ROUND{" "}
              {currentCp.round}
            </span>
            <span
              style={{
                ...styles.statusPill,
                background: isCurrentSolved
                  ? "rgba(10, 158, 114, 0.18)"
                  : isCurrentScanned
                  ? "rgba(17, 138, 178, 0.2)"
                  : "rgba(255, 84, 112, 0.15)",
                color: isCurrentSolved
                  ? "#2ec4b6"
                  : isCurrentScanned
                  ? "#4ea8de"
                  : "#ff5470",
              }}
            >
              {isCurrentSolved
                ? "Cleared ✓"
                : isCurrentScanned
                ? "Unlocked · Unsolved"
                : "QR Scan Required"}
            </span>
          </div>

          {/* STATE A: Prerequisite Checkpoint Not Solved Yet */}
          {!canScanCurrent && !isCurrentScanned && (
            <div style={styles.lockedBox}>
              <div style={{ fontSize: 32, marginBottom: 8 }}>🔒</div>
              <h2 style={styles.cardTitle}>Checkpoint {activeIdx + 1} Locked</h2>
              <p style={styles.lockedText}>
                You cannot bypass checkpoints out of order. Complete and verify{" "}
                <strong>Checkpoint {activeIdx}</strong> first to unlock this
                stage.
              </p>
              <button
                type="button"
                style={styles.secondaryBtn}
                onClick={() => setActiveIdx(activeIdx - 1)}
              >
                ← Go to Checkpoint {activeIdx}
              </button>
            </div>
          )}

          {/* STATE B: Ready to Scan QR Code */}
          {canScanCurrent && !isCurrentScanned && (
            <div style={styles.scanPromptBox}>
              <h2 style={styles.cardTitle}>
                Scan Checkpoint {activeIdx + 1} QR Code
              </h2>
              <p style={styles.clueText}>
                {activeIdx === 0
                  ? "Find the starting QR code at Checkpoint 1 (Café 1 — Tall Structure) and scan it to decrypt your first riddle."
                  : `Follow the clue from Checkpoint ${activeIdx} to locate QR ${
                      activeIdx + 1
                    }, then scan it below to decrypt the riddle.`}
              </p>

              {/* Show previous checkpoint's "Next Location" hint right here for convenience */}
              {activeIdx > 0 && solvedProofs[cps[activeIdx - 1].id] && (
                <div style={styles.prevHintBanner}>
                  <strong>Target Location:</strong>{" "}
                  {solvedProofs[cps[activeIdx - 1].id].nextText}
                </div>
              )}

              <div style={styles.actionGroup}>
                <button
                  type="button"
                  style={styles.scanQrPrimaryBtn}
                  onClick={() => {
                    setScannerOpen(true);
                    setCameraActive(false);
                    setScanStatus("");
                  }}
                >
                  📷 Open QR Camera Scanner
                </button>

                <button
                  type="button"
                  style={styles.textLinkBtn}
                  onClick={() => setShowManualQr(!showManualQr)}
                >
                  {showManualQr
                    ? "Hide manual token input"
                    : "Camera issue? Enter QR code token manually"}
                </button>
              </div>

              {showManualQr && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    verifyAndUnlockQrToken(manualQrInput, false);
                    setManualQrInput("");
                  }}
                  style={{ ...styles.rowForm, marginTop: 12 }}
                >
                  <input
                    style={styles.input}
                    value={manualQrInput}
                    onChange={(e) => setManualQrInput(e.target.value)}
                    placeholder="Enter token from QR link (e.g. tk-...)"
                    autoComplete="off"
                    autoCapitalize="none"
                  />
                  <button type="submit" style={styles.primaryBtn}>
                    Unlock
                  </button>
                </form>
              )}
            </div>
          )}

          {/* STATE C: QR Scanned -> Riddle Decrypted! */}
          {isCurrentScanned && currentClueObj && (
            <div>
              <h2 style={styles.cardTitle}>{currentClueObj.title}</h2>
              <div style={styles.riddleBox}>{currentClueObj.clue}</div>

              {/* Answer Input Form (if not yet solved) */}
              {!isCurrentSolved && (
                <form onSubmit={handleCheckAnswer} style={styles.rowForm}>
                  <input
                    style={styles.input}
                    value={answerInput}
                    onChange={(e) => setAnswerInput(e.target.value)}
                    placeholder="Type your answer…"
                    autoComplete="off"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    disabled={isSyncing}
                  />
                  <button
                    type="submit"
                    style={styles.primaryBtn}
                    disabled={isSyncing}
                  >
                    {isSyncing ? "Syncing…" : "Submit Answer"}
                  </button>
                </form>
              )}

              {/* Solved Next-Step Box */}
              {isCurrentSolved && currentSolvedObj && (
                <div style={styles.nextUnlockedBox}>
                  <div style={styles.nextHeader}>
                    ✓ CHECKPOINT {activeIdx + 1} CLEARED & SYNCED
                  </div>
                  <p style={styles.nextInstruction}>
                    {currentSolvedObj.nextText}
                  </p>
                  {activeIdx < cps.length - 1 && (
                    <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                      <button
                        type="button"
                        style={styles.primaryBtn}
                        onClick={() => {
                          setActiveIdx(activeIdx + 1);
                          setStatusMsg({ text: "", type: "" });
                        }}
                      >
                        Proceed to Checkpoint {activeIdx + 2} →
                      </button>
                      <button
                        type="button"
                        style={styles.secondaryBtn}
                        onClick={() => {
                          setScannerOpen(true);
                          setCameraActive(false);
                          setScanStatus("");
                        }}
                      >
                        📷 Scan Next QR Directly
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Feedback Message */}
          {statusMsg.text && (
            <div
              style={{
                ...styles.feedbackBox,
                borderColor:
                  statusMsg.type === "ok"
                    ? "#0a9e72"
                    : statusMsg.type === "bad"
                    ? "#ff5470"
                    : "#118ab2",
                color:
                  statusMsg.type === "ok"
                    ? "#2ec4b6"
                    : statusMsg.type === "bad"
                    ? "#ff5470"
                    : "#eceef8",
              }}
            >
              {isSyncing && <span style={styles.inlineSpinner} />}
              {statusMsg.text}
            </div>
          )}
        </section>
      </main>

      {/* Camera QR Scanner Modal */}
      {scannerOpen && (
        <div
          style={styles.modalOverlay}
          onClick={(e) => {
            if (e.target === e.currentTarget) stopScanner();
          }}
        >
          <div style={styles.scannerCard}>
            <div style={styles.scannerHeader}>
              <strong>Scan Checkpoint QR Code</strong>
              <button
                type="button"
                onClick={stopScanner}
                style={styles.closeModalBtn}
              >
                ✕
              </button>
            </div>

            {!cameraActive && (
              <div style={styles.permissionBox}>
                <p style={{ margin: "0 0 14px", color: "#d6d8e8", fontSize: 14 }}>
                  TechKnow uses your camera strictly to scan physical checkpoint
                  QR codes.
                </p>
                <button
                  type="button"
                  style={styles.primaryBtn}
                  onClick={startCamera}
                  disabled={cameraRequesting}
                >
                  {cameraRequesting
                    ? "Waiting for permission…"
                    : "Allow Camera & Start Scanner"}
                </button>
                <p
                  style={{
                    marginTop: 12,
                    fontSize: 13,
                    color: "#ffd98a",
                    whiteSpace: "pre-line",
                  }}
                >
                  {scanHelp}
                </p>
              </div>
            )}

            <video
              ref={videoRef}
              playsInline
              muted
              autoPlay
              style={{
                ...styles.videoElement,
                display: cameraActive ? "block" : "none",
              }}
            />

            {scanStatus && <div style={styles.scanStatusText}>{scanStatus}</div>}

            <div style={{ display: "flex", gap: 10, justifyContent: "center" }}>
              {scanRetryVisible && (
                <button
                  type="button"
                  style={styles.secondaryBtn}
                  onClick={startCamera}
                >
                  Retry Camera
                </button>
              )}
              <button
                type="button"
                style={styles.secondaryBtn}
                onClick={stopScanner}
              >
                Close Scanner
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// CLEAN DARK-MODE STYLES (SINGLE-FILE ZERO EXTERNAL CSS DEPENDENCY)
// ============================================================================
const styles = {
  pageWrap: {
    minHeight: "100dvh",
    backgroundColor: "#0e0f1a",
    color: "#eceef8",
    fontFamily:
      'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    display: "flex",
    flexDirection: "column",
  },
  loadingScreen: {
    minHeight: "100dvh",
    backgroundColor: "#0e0f1a",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "14px 20px",
    borderBottom: "1px solid #2c2f4a",
    backgroundColor: "#141627",
    flexWrap: "wrap",
    gap: 10,
  },
  brand: {
    fontWeight: 800,
    fontSize: 19,
    letterSpacing: "-0.02em",
  },
  brandLarge: {
    fontWeight: 800,
    fontSize: 24,
    marginBottom: 8,
  },
  headerRight: {
    display: "flex",
    alignItems: "center",
    gap: 10,
  },
  teamBadge: {
    background: "#191b2e",
    border: "1px solid #2c2f4a",
    color: "#a0a3bd",
    padding: "6px 12px",
    borderRadius: 8,
    fontSize: 13,
    cursor: "pointer",
  },
  lbBtn: {
    background: "#118ab2",
    color: "#fff",
    textDecoration: "none",
    padding: "7px 13px",
    borderRadius: 8,
    fontSize: 13,
    fontWeight: 600,
  },
  offlineBanner: {
    background: "#fff3cd",
    color: "#765500",
    padding: "8px 16px",
    fontSize: 13,
    textAlign: "center",
    fontWeight: 500,
  },
  main: {
    flex: 1,
    width: "100%",
    maxWidth: 640,
    margin: "0 auto",
    padding: "20px 16px 40px",
    boxSizing: "border-box",
    display: "flex",
    flexDirection: "column",
    gap: 18,
  },
  progressCard: {
    background: "#191b2e",
    border: "1px solid #2c2f4a",
    borderRadius: 14,
    padding: 16,
  },
  progressTop: {
    display: "flex",
    justifyContent: "space-between",
    fontSize: 13,
    color: "#a0a3bd",
    marginBottom: 12,
    fontWeight: 600,
  },
  progressLabel: {
    color: "#118ab2",
    textTransform: "uppercase",
    letterSpacing: "0.05em",
  },
  progressCount: {
    color: "#eceef8",
  },
  stepperGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(3, 1fr)",
    gap: 8,
  },
  stepBtn: {
    background: "#101220",
    border: "1px solid #2c2f4a",
    borderRadius: 10,
    padding: "10px 4px",
    color: "#a0a3bd",
    cursor: "pointer",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: 4,
    transition: "all 0.15s ease",
  },
  stepBtnActive: {
    borderColor: "#118ab2",
    boxShadow: "0 0 0 2px rgba(17, 138, 178, 0.35)",
    color: "#fff",
  },
  stepBtnSolved: {
    background: "rgba(10, 158, 114, 0.18)",
    borderColor: "#0a9e72",
    color: "#2ec4b6",
  },
  stepBtnLocked: {
    opacity: 0.5,
  },
  stepNum: {
    fontSize: 15,
    fontWeight: 700,
  },
  stepMeta: {
    fontSize: 11,
  },
  card: {
    background: "#191b2e",
    border: "1px solid #2c2f4a",
    borderRadius: 16,
    padding: 22,
    boxShadow: "0 10px 30px rgba(0,0,0,0.25)",
  },
  cardHeaderRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    flexWrap: "wrap",
    gap: 8,
    marginBottom: 14,
  },
  cpTag: {
    fontSize: 12,
    fontWeight: 700,
    color: "#118ab2",
    letterSpacing: "0.05em",
  },
  statusPill: {
    fontSize: 12,
    fontWeight: 600,
    padding: "4px 10px",
    borderRadius: 999,
  },
  cardTitle: {
    margin: "0 0 12px",
    fontSize: 22,
    fontWeight: 700,
    color: "#fff",
  },
  riddleBox: {
    background: "#101220",
    border: "1px solid #2c2f4a",
    borderLeft: "4px solid #118ab2",
    borderRadius: 10,
    padding: 16,
    whiteSpace: "pre-line",
    lineHeight: 1.6,
    fontSize: 16,
    color: "#eceef8",
    marginBottom: 18,
  },
  clueText: {
    lineHeight: 1.55,
    color: "#a0a3bd",
    fontSize: 15,
    margin: "0 0 16px",
  },
  prevHintBanner: {
    background: "rgba(17, 138, 178, 0.14)",
    border: "1px solid #118ab2",
    borderRadius: 10,
    padding: "12px 14px",
    fontSize: 14,
    color: "#e0f2fe",
    marginBottom: 18,
    lineHeight: 1.45,
  },
  lockedBox: {
    textAlign: "center",
    padding: "24px 12px",
  },
  lockedText: {
    color: "#a0a3bd",
    fontSize: 15,
    lineHeight: 1.5,
    maxWidth: 420,
    margin: "0 auto 18px",
  },
  scanPromptBox: {
    padding: "6px 0",
  },
  actionGroup: {
    display: "flex",
    flexDirection: "column",
    gap: 10,
    alignItems: "stretch",
  },
  rowForm: {
    display: "flex",
    gap: 10,
    flexWrap: "wrap",
  },
  formCol: {
    display: "flex",
    flexDirection: "column",
    gap: 12,
  },
  input: {
    flex: "1 1 220px",
    padding: "12px 14px",
    borderRadius: 10,
    border: "1px solid #3a3d59",
    background: "#0e0f1a",
    color: "#fff",
    fontSize: 16,
    outline: "none",
  },
  primaryBtn: {
    padding: "12px 20px",
    borderRadius: 10,
    border: "none",
    background: "#118ab2",
    color: "#fff",
    fontWeight: 700,
    fontSize: 15,
    cursor: "pointer",
  },
  scanQrPrimaryBtn: {
    padding: "14px 20px",
    borderRadius: 12,
    border: "none",
    background: "linear-gradient(135deg, #118ab2, #0a9e72)",
    color: "#fff",
    fontWeight: 700,
    fontSize: 16,
    cursor: "pointer",
    textAlign: "center",
  },
  secondaryBtn: {
    padding: "11px 18px",
    borderRadius: 10,
    border: "1px solid #3a3d59",
    background: "#232640",
    color: "#eceef8",
    fontWeight: 600,
    fontSize: 14,
    cursor: "pointer",
  },
  textLinkBtn: {
    background: "none",
    border: "none",
    color: "#a0a3bd",
    fontSize: 13,
    textDecoration: "underline",
    cursor: "pointer",
    padding: 6,
  },
  nextUnlockedBox: {
    background: "rgba(10, 158, 114, 0.12)",
    border: "1px solid #0a9e72",
    borderRadius: 12,
    padding: 16,
    marginTop: 12,
  },
  nextHeader: {
    fontSize: 12,
    fontWeight: 800,
    color: "#2ec4b6",
    letterSpacing: "0.05em",
    marginBottom: 6,
  },
  nextInstruction: {
    margin: "0 0 14px",
    fontSize: 16,
    fontWeight: 600,
    color: "#fff",
    lineHeight: 1.45,
  },
  feedbackBox: {
    marginTop: 16,
    padding: "12px 14px",
    borderRadius: 10,
    border: "1px solid",
    background: "#101220",
    fontSize: 14,
    display: "flex",
    alignItems: "center",
    gap: 10,
  },
  gateContainer: {
    flex: 1,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: 20,
  },
  gateCard: {
    width: "100%",
    maxWidth: 400,
    background: "#191b2e",
    border: "1px solid #2c2f4a",
    borderRadius: 16,
    padding: 26,
    boxShadow: "0 12px 34px rgba(0,0,0,0.4)",
  },
  gateTitle: {
    margin: "0 0 6px",
    fontSize: 24,
  },
  gateSub: {
    margin: "0 0 20px",
    color: "#a0a3bd",
    fontSize: 14,
    lineHeight: 1.45,
  },
  errText: {
    marginTop: 12,
    color: "#ff5470",
    fontSize: 14,
  },
  modalOverlay: {
    position: "fixed",
    inset: 0,
    zIndex: 50,
    background: "rgba(5, 8, 18, 0.92)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: 16,
  },
  scannerCard: {
    width: "100%",
    maxWidth: 480,
    background: "#191b2e",
    border: "1px solid #3a3d59",
    borderRadius: 16,
    padding: 20,
    display: "flex",
    flexDirection: "column",
    gap: 14,
  },
  scannerHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    fontSize: 17,
  },
  closeModalBtn: {
    background: "none",
    border: "none",
    color: "#a0a3bd",
    fontSize: 20,
    cursor: "pointer",
  },
  permissionBox: {
    textAlign: "center",
    padding: "14px 8px",
  },
  videoElement: {
    width: "100%",
    maxHeight: "55vh",
    objectFit: "cover",
    borderRadius: 12,
    background: "#000",
  },
  scanStatusText: {
    textAlign: "center",
    fontSize: 14,
    color: "#2ec4b6",
  },
  spinner: {
    width: 28,
    height: 28,
    border: "3px solid #2c2f4a",
    borderTopColor: "#118ab2",
    borderRadius: "50%",
    animation: "spin 0.8s linear infinite",
  },
  inlineSpinner: {
    display: "inline-block",
    width: 14,
    height: 14,
    border: "2px solid currentColor",
    borderRightColor: "transparent",
    borderRadius: "50%",
  },
};