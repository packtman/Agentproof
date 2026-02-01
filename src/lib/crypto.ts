/**
 * Cryptographic utilities for AgentProof
 * Ed25519 signature verification and key handling
 */

import { createHash } from "crypto";

/**
 * Create the message that agents must sign
 */
export function createSigningMessage(nonce: string, agentName: string): string {
  return `agentproof:${nonce}:${agentName}`;
}

/**
 * Hash a message using SHA256
 */
export function sha256(message: string): Uint8Array {
  const hash = createHash("sha256");
  hash.update(message);
  return new Uint8Array(hash.digest());
}

/**
 * Verify an Ed25519 signature
 * @param publicKey - Base64 encoded Ed25519 public key
 * @param signature - Base64 encoded signature
 * @param message - The original message that was signed
 */
export async function verifyEd25519Signature(
  publicKey: string,
  signature: string,
  message: string
): Promise<boolean> {
  try {
    // Decode base64 inputs
    const pubKeyBytes = base64ToBytes(publicKey);
    const sigBytes = base64ToBytes(signature);
    
    // Create the message hash
    const messageHash = sha256(message);
    
    // Import the public key
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      pubKeyBytes.buffer as ArrayBuffer,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    
    // Verify the signature
    const isValid = await crypto.subtle.verify(
      "Ed25519",
      cryptoKey,
      sigBytes.buffer as ArrayBuffer,
      messageHash.buffer as ArrayBuffer
    );
    
    return isValid;
  } catch (error) {
    console.error("Signature verification error:", error);
    return false;
  }
}

/**
 * Generate a random nonce for challenges
 */
export function generateNonce(length: number = 32): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * Generate a random token (for claim URLs, etc.)
 */
export function generateToken(length: number = 24): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

/**
 * Hash an API key for storage
 */
export async function hashApiKey(apiKey: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(apiKey);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(hashBuffer));
}

/**
 * Generate a new API key
 */
export function generateApiKey(prefix: string): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return `${prefix}_${bytesToBase64Url(bytes)}`;
}

// Utility functions for encoding/decoding

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export function base64ToBytes(base64: string): Uint8Array {
  // Handle both standard and URL-safe base64
  const normalized = base64.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function base64UrlToBytes(base64url: string): Uint8Array {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (base64.length % 4)) % 4);
  return base64ToBytes(base64 + padding);
}
