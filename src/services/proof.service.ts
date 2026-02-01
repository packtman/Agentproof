/**
 * Proof Service
 * Handles agent creation and proof token generation
 */

import { getDb, generateId } from "../db/index.js";
import { signProofToken, type AgentProofPayload } from "../lib/jwt.js";
import { generateToken } from "../lib/crypto.js";

export interface Agent {
  id: string;
  name: string;
  description?: string;
  public_key: string;
  status: string;
  capabilities: string[];
  model_family?: string;
  framework?: string;
  claim_token?: string;
  claim_expires_at?: string;
  owner_id?: string;
  verified_at?: string;
  created_at: string;
}

export interface Proof {
  id: string;
  agent_id: string;
  challenge_id: string;
  token: string;
  issued_at: string;
  expires_at: string;
  status: string;
}

/**
 * Create a new verified agent and generate proof token
 */
export async function createVerifiedAgent(
  name: string,
  description: string | undefined,
  publicKey: string,
  capabilities: string[],
  modelFamily: string | undefined,
  framework: string | undefined,
  challengeId: string,
  difficulty: string,
  tasksPassed: string[],
  timeTakenMs: number
): Promise<{ agent: Agent; proof: Proof }> {
  const db = getDb();
  
  // Check if agent with this public key already exists
  const existing = db
    .prepare("SELECT id FROM agents WHERE public_key = ?")
    .get(publicKey) as { id: string } | null;

  if (existing) {
    throw new Error("An agent with this public key already exists");
  }

  // Create agent
  const agentId = generateId("agt");
  const claimToken = generateToken(24);
  const claimExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(); // 7 days
  const verifiedAt = new Date().toISOString();

  db.prepare(
    `INSERT INTO agents (id, name, description, public_key, status, capabilities, model_family, framework, claim_token, claim_expires_at, verified_at)
     VALUES (?, ?, ?, ?, 'verified', ?, ?, ?, ?, ?, ?)`
  ).run(
    agentId,
    name,
    description,
    publicKey,
    JSON.stringify(capabilities),
    modelFamily,
    framework,
    claimToken,
    claimExpiresAt,
    verifiedAt
  );

  // Generate proof token
  const proofId = generateId("prf");
  const expiresInDays = parseInt(process.env.PROOF_EXPIRY_DAYS || "365", 10);
  const proofExpiresAt = new Date(
    Date.now() + expiresInDays * 24 * 60 * 60 * 1000
  ).toISOString();

  const payload: AgentProofPayload = {
    version: "1.0",
    challenge_id: challengeId,
    difficulty,
    tasks_passed: tasksPassed,
    time_taken_ms: timeTakenMs,
    agent: {
      name,
      public_key: publicKey,
      capabilities,
    },
  };

  const token = await signProofToken(agentId, proofId, payload, expiresInDays);

  // Store proof
  db.prepare(
    `INSERT INTO proofs (id, agent_id, challenge_id, token, expires_at)
     VALUES (?, ?, ?, ?, ?)`
  ).run(proofId, agentId, challengeId, token, proofExpiresAt);

  const baseUrl = process.env.BASE_URL || "https://knowyourclaw.com";

  const agent: Agent = {
    id: agentId,
    name,
    description,
    public_key: publicKey,
    status: "verified",
    capabilities,
    model_family: modelFamily,
    framework,
    claim_token: claimToken,
    claim_expires_at: claimExpiresAt,
    verified_at: verifiedAt,
    created_at: verifiedAt,
  };

  const proof: Proof = {
    id: proofId,
    agent_id: agentId,
    challenge_id: challengeId,
    token,
    issued_at: verifiedAt,
    expires_at: proofExpiresAt,
    status: "active",
  };

  return { agent, proof };
}

/**
 * Get agent by ID
 */
export function getAgent(agentId: string): Agent | null {
  const db = getDb();
  const row = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as any;

  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    description: row.description,
    public_key: row.public_key,
    status: row.status,
    capabilities: JSON.parse(row.capabilities || "[]"),
    model_family: row.model_family,
    framework: row.framework,
    claim_token: row.claim_token,
    claim_expires_at: row.claim_expires_at,
    owner_id: row.owner_id,
    verified_at: row.verified_at,
    created_at: row.created_at,
  };
}

/**
 * Get agent by public key
 */
export function getAgentByPublicKey(publicKey: string): Agent | null {
  const db = getDb();
  const row = db
    .prepare("SELECT * FROM agents WHERE public_key = ?")
    .get(publicKey) as any;

  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    description: row.description,
    public_key: row.public_key,
    status: row.status,
    capabilities: JSON.parse(row.capabilities || "[]"),
    model_family: row.model_family,
    framework: row.framework,
    claim_token: row.claim_token,
    claim_expires_at: row.claim_expires_at,
    owner_id: row.owner_id,
    verified_at: row.verified_at,
    created_at: row.created_at,
  };
}

/**
 * Get proof by ID
 */
export function getProof(proofId: string): Proof | null {
  const db = getDb();
  const row = db.prepare("SELECT * FROM proofs WHERE id = ?").get(proofId) as any;

  if (!row) return null;

  return {
    id: row.id,
    agent_id: row.agent_id,
    challenge_id: row.challenge_id,
    token: row.token,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
    status: row.status,
  };
}

/**
 * Get proof by agent ID
 */
export function getProofByAgentId(agentId: string): Proof | null {
  const db = getDb();
  const row = db
    .prepare("SELECT * FROM proofs WHERE agent_id = ? AND status = 'active' ORDER BY issued_at DESC LIMIT 1")
    .get(agentId) as any;

  if (!row) return null;

  return {
    id: row.id,
    agent_id: row.agent_id,
    challenge_id: row.challenge_id,
    token: row.token,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
    status: row.status,
  };
}

/**
 * Record a proof verification
 */
export function recordVerification(proofId: string, platformId: string): void {
  const db = getDb();
  db.prepare(
    `UPDATE proofs 
     SET times_verified = times_verified + 1, 
         last_verified_at = datetime('now'),
         last_verified_by = ?
     WHERE id = ?`
  ).run(platformId, proofId);
}

/**
 * Revoke a proof
 */
export function revokeProof(proofId: string, reason: string): void {
  const db = getDb();
  db.prepare(
    `UPDATE proofs 
     SET status = 'revoked', revoked_at = datetime('now'), revoke_reason = ?
     WHERE id = ?`
  ).run(reason, proofId);
}
