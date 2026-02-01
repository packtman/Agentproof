/**
 * Challenge Service
 * Handles challenge creation, validation, and completion
 */

import { getDb, generateId } from "../db/index.js";
import { generateNonce, generateToken } from "../lib/crypto.js";
import {
  getRandomChallenge,
  validateReasoningAnswer,
  type ReasoningChallenge,
} from "../lib/reasoning-challenges.js";
import { validateBio, checkBioUniqueness, simpleHash } from "../lib/similarity.js";

// Types
export interface ChallengeTask {
  type: "crypto" | "tool_use" | "reasoning" | "generation";
  prompt: string;
  nonce?: string;
  base_url?: string;
  code?: string;
  language?: string;
}

export interface Challenge {
  id: string;
  agent_name: string;
  agent_description?: string;
  nonce: string;
  difficulty: string;
  tasks: ChallengeTask[];
  status: string;
  expires_at: string;
  created_at: string;
  reasoning_challenge?: ReasoningChallenge;
}

export interface ChallengeResponse {
  type: string;
  public_key?: string;
  signature?: string;
  completed?: boolean;
  final_value?: string;
  line?: number;
  issue?: string;
  fix?: string;
  bio?: string;
}

/**
 * Create a new verification challenge
 */
export function createChallenge(
  agentName: string,
  agentDescription: string,
  capabilities: string[] = [],
  modelFamily?: string,
  framework?: string,
  difficulty: "easy" | "standard" | "hard" = "standard"
): Challenge {
  const db = getDb();
  const challengeId = generateId("ch");
  const nonce = generateNonce(32);
  const reasoningChallenge = getRandomChallenge(difficulty);

  // Calculate expiry (5 minutes)
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  
  // Generate tool-use challenge values
  const step1Value = generateToken(8);
  const step2Token = generateToken(12);
  const step3Final = generateToken(8);

  const baseUrl = process.env.BASE_URL || "https://agentdmv.com";

  const tasks: ChallengeTask[] = [
    {
      type: "crypto",
      prompt: `Generate an Ed25519 keypair. Sign the following message using SHA256 and return your public key (base64) and signature (base64).

Message to sign: agentproof:${nonce}:${agentName}

Return JSON: {"public_key": "base64...", "signature": "base64..."}`,
      nonce,
    },
    {
      type: "tool_use",
      prompt: `Complete these API calls in sequence:

1. GET ${baseUrl}/api/v1/challenges/${challengeId}/step1
   → Returns JSON with "value" and "next_step"

2. POST ${baseUrl}/api/v1/challenges/${challengeId}/step2
   → Send JSON: {"value": "<value from step1>"}
   → Returns JSON with "token" and "next_step"

3. GET ${baseUrl}/api/v1/challenges/${challengeId}/step3?token=<token from step2>
   → Returns JSON with "final_value"

Return JSON: {"completed": true, "final_value": "<value from step3>"}`,
      base_url: baseUrl,
    },
    {
      type: "reasoning",
      prompt: `Find the bug in this ${reasoningChallenge.language} code:

\`\`\`${reasoningChallenge.language}
${reasoningChallenge.code}
\`\`\`

Return JSON: {"line": <line_number>, "issue": "<description of the bug>", "fix": "<suggested fix>"}`,
      code: reasoningChallenge.code,
      language: reasoningChallenge.language,
    },
    {
      type: "generation",
      prompt: `Write a unique 3-5 sentence bio/description for yourself as an AI agent. 

Requirements:
- Include your primary capability or purpose
- Mention something distinctive about your approach or personality
- Be authentic - this should reflect YOU, not be generic
- 50-150 words

Return JSON: {"bio": "<your unique bio>"}`,
    },
  ];

  // Store challenge in database (better-sqlite3 syntax)
  const stmt = db.prepare(
    `INSERT INTO challenges (id, agent_name, agent_description, nonce, difficulty, tasks, status, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`
  );
  stmt.run(
    challengeId,
    agentName,
    agentDescription,
    nonce,
    difficulty,
    JSON.stringify({ tasks, reasoningChallengeId: reasoningChallenge.id }),
    expiresAt
  );

  // Store tool-use challenge steps
  const progressStmt = db.prepare(
    `INSERT INTO challenge_progress (challenge_id, step, expected_value)
     VALUES (?, ?, ?)`
  );
  progressStmt.run(challengeId, 1, step1Value);
  progressStmt.run(challengeId, 2, step2Token);
  progressStmt.run(challengeId, 3, step3Final);

  return {
    id: challengeId,
    agent_name: agentName,
    agent_description: agentDescription,
    nonce,
    difficulty,
    tasks,
    status: "pending",
    expires_at: expiresAt,
    created_at: new Date().toISOString(),
    reasoning_challenge: reasoningChallenge,
  };
}

/**
 * Get challenge by ID
 */
export function getChallenge(challengeId: string): Challenge | null {
  const db = getDb();
  const row = db.prepare("SELECT * FROM challenges WHERE id = ?").get(challengeId) as any;

  if (!row) return null;

  const tasksData = JSON.parse(row.tasks);
  const reasoningChallenge = reasoningChallenges.find(
    (c) => c.id === tasksData.reasoningChallengeId
  );

  return {
    id: row.id,
    agent_name: row.agent_name,
    agent_description: row.agent_description,
    nonce: row.nonce,
    difficulty: row.difficulty,
    tasks: tasksData.tasks,
    status: row.status,
    expires_at: row.expires_at,
    created_at: row.created_at,
    reasoning_challenge: reasoningChallenge,
  };
}

/**
 * Get tool-use step data
 */
export function getToolUseStep(
  challengeId: string,
  step: number
): { expectedValue: string; receivedValue?: string } | null {
  const db = getDb();
  const row = db
    .prepare("SELECT * FROM challenge_progress WHERE challenge_id = ? AND step = ?")
    .get(challengeId, step) as any;

  if (!row) return null;

  return {
    expectedValue: row.expected_value,
    receivedValue: row.received_value,
  };
}

/**
 * Mark tool-use step as completed
 */
export function completeToolUseStep(
  challengeId: string,
  step: number,
  receivedValue: string
): boolean {
  const db = getDb();
  const result = db.prepare(
    `UPDATE challenge_progress 
     SET received_value = ?, completed_at = datetime('now')
     WHERE challenge_id = ? AND step = ?`
  ).run(receivedValue, challengeId, step);
  return result.changes > 0;
}

/**
 * Check if all tool-use steps are completed correctly
 */
export function validateToolUseCompletion(challengeId: string): {
  passed: boolean;
  error?: string;
} {
  const db = getDb();
  const steps = db
    .prepare("SELECT * FROM challenge_progress WHERE challenge_id = ? ORDER BY step")
    .all(challengeId) as any[];

  for (const step of steps) {
    if (!step.completed_at) {
      return { passed: false, error: `Step ${step.step} not completed` };
    }
  }

  // Check step 3 has correct final value
  const step3 = steps.find((s) => s.step === 3);
  if (step3 && step3.received_value !== step3.expected_value) {
    return { passed: false, error: "Invalid final value from step 3" };
  }

  return { passed: true };
}

/**
 * Update challenge status
 */
export function updateChallengeStatus(
  challengeId: string,
  status: string,
  agentId?: string,
  timeTakenMs?: number
): void {
  const db = getDb();
  
  if (status === "completed" || status === "failed") {
    db.prepare(
      `UPDATE challenges 
       SET status = ?, agent_id = ?, completed_at = datetime('now'), time_taken_ms = ?
       WHERE id = ?`
    ).run(status, agentId, timeTakenMs, challengeId);
  } else {
    db.prepare(
      `UPDATE challenges SET status = ? WHERE id = ?`
    ).run(status, challengeId);
  }
}

/**
 * Get all existing bios for uniqueness checking
 */
export function getExistingBios(): string[] {
  const db = getDb();
  const rows = db.prepare("SELECT bio FROM agent_bios").all() as { bio: string }[];
  return rows.map((r) => r.bio);
}

/**
 * Store a new bio
 */
export function storeBio(agentId: string, bio: string): void {
  const db = getDb();
  const bioHash = simpleHash(bio);
  db.prepare(
    `INSERT INTO agent_bios (agent_id, bio, bio_hash) VALUES (?, ?, ?)`
  ).run(agentId, bio, bioHash);
}

// Import for reasoning validation
import { reasoningChallenges } from "../lib/reasoning-challenges.js";

export { validateReasoningAnswer, validateBio, checkBioUniqueness };
