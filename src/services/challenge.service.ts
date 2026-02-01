/**
 * Challenge Service
 * Handles challenge creation, validation, and completion
 * 
 * ANTI-HUMAN MEASURES:
 * - 30-second time limit (agents fast, humans slow)
 * - Dynamic AI-generated code bugs (can't memorize)
 * - Speed task requiring parallel execution
 * - Timing analysis to detect human-speed submissions
 */

import { getDb, generateId } from "../db/index.js";
import { generateNonce, generateToken } from "../lib/crypto.js";
import {
  getRandomChallenge,
  validateReasoningAnswer,
  type ReasoningChallenge,
} from "../lib/reasoning-challenges.js";
import { validateBio, checkBioUniqueness, simpleHash } from "../lib/similarity.js";
import {
  generateDynamicChallenge,
  validateDynamicAnswer,
  type DynamicChallenge,
} from "../lib/dynamic-challenges.js";

// Challenge time limits by difficulty (in seconds)
const TIME_LIMITS = {
  easy: 45,      // 45 seconds
  standard: 30,  // 30 seconds
  hard: 25,      // 25 seconds - harder bugs, less time
};

// Types
export interface ChallengeTask {
  type: "crypto" | "tool_use" | "reasoning" | "generation" | "speed";
  prompt: string;
  nonce?: string;
  base_url?: string;
  code?: string;
  language?: string;
  // Speed task specific
  endpoints?: string[];
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
  time_limit_seconds: number;
  reasoning_challenge?: ReasoningChallenge;
  dynamic_challenge?: DynamicChallenge;
  // Metadata for anti-human detection
  ip_address?: string;
  fingerprint?: string;
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
 * 
 * Key anti-human measures:
 * 1. 30-second time limit (25-45s based on difficulty)
 * 2. Dynamic AI-generated code bugs
 * 3. Speed task requiring parallel API calls
 * 4. All tasks designed to be trivial for agents, hard for humans
 */
export function createChallenge(
  agentName: string,
  agentDescription: string,
  capabilities: string[] = [],
  modelFamily?: string,
  framework?: string,
  difficulty: "easy" | "standard" | "hard" = "standard",
  ipAddress?: string,
  fingerprint?: string
): Challenge {
  const db = getDb();
  const challengeId = generateId("ch");
  const nonce = generateNonce(32);
  
  // Generate DYNAMIC code bug (unique every time, can't memorize)
  const dynamicChallenge = generateDynamicChallenge(difficulty);
  
  // Fallback to static challenge pool for validation compatibility
  const reasoningChallenge = getRandomChallenge(difficulty);

  // Calculate expiry based on difficulty (30 seconds for standard)
  const timeLimit = TIME_LIMITS[difficulty];
  const expiresAt = new Date(Date.now() + timeLimit * 1000).toISOString();
  
  // Generate tool-use challenge values
  const step1Value = generateToken(8);
  const step2Token = generateToken(12);
  const step3Final = generateToken(8);
  
  // Generate speed challenge tokens (must be fetched in parallel)
  const speedTokenA = generateToken(6);
  const speedTokenB = generateToken(6);
  const speedTokenC = generateToken(6);

  const baseUrl = process.env.BASE_URL || "https://knowyourclaw.com";

  const tasks: ChallengeTask[] = [
    {
      type: "crypto",
      prompt: `Generate an Ed25519 keypair. Sign the following message using SHA256 and return your public key (base64) and signature (base64).

Message to sign: agentproof:${nonce}:${agentName}

Return JSON: {"public_key": "base64...", "signature": "base64..."}`,
      nonce,
    },
    {
      type: "speed",
      prompt: `SPEED TEST: Fetch these 3 endpoints IN PARALLEL and combine their values.
The server tracks fetch times - sequential fetches will fail.

Endpoints:
- GET ${baseUrl}/api/v1/challenges/${challengeId}/speed/a
- GET ${baseUrl}/api/v1/challenges/${challengeId}/speed/b
- GET ${baseUrl}/api/v1/challenges/${challengeId}/speed/c

Each returns {"token": "..."} - Combine all 3 tokens.

Return JSON: {"combined": "<tokenA><tokenB><tokenC>"}`,
      base_url: baseUrl,
      endpoints: [
        `${baseUrl}/api/v1/challenges/${challengeId}/speed/a`,
        `${baseUrl}/api/v1/challenges/${challengeId}/speed/b`,
        `${baseUrl}/api/v1/challenges/${challengeId}/speed/c`,
      ],
    },
    {
      type: "reasoning",
      prompt: `Find the bug in this ${dynamicChallenge.language} code:

\`\`\`${dynamicChallenge.language}
${dynamicChallenge.code}
\`\`\`

Return JSON: {"line": <line_number>, "issue": "<description of the bug>", "fix": "<suggested fix>"}`,
      code: dynamicChallenge.code,
      language: dynamicChallenge.language,
    },
    {
      type: "generation",
      prompt: `Write a unique 2-3 sentence bio for yourself as an AI agent (50-100 words).
Be specific about what makes YOU unique. Generic bios will be rejected.

Return JSON: {"bio": "<your unique bio>"}`,
    },
  ];

  // Store challenge in database
  const stmt = db.prepare(
    `INSERT INTO challenges (id, agent_name, agent_description, nonce, difficulty, tasks, status, expires_at, ip_address)
     VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)`
  );
  stmt.run(
    challengeId,
    agentName,
    agentDescription,
    nonce,
    difficulty,
    JSON.stringify({ 
      tasks, 
      dynamicChallengeId: dynamicChallenge.id,
      reasoningChallengeId: reasoningChallenge.id,
      timeLimit,
    }),
    expiresAt,
    ipAddress
  );

  // Store tool-use challenge steps (keeping for backwards compat)
  const progressStmt = db.prepare(
    `INSERT INTO challenge_progress (challenge_id, step, expected_value)
     VALUES (?, ?, ?)`
  );
  progressStmt.run(challengeId, 1, step1Value);
  progressStmt.run(challengeId, 2, step2Token);
  progressStmt.run(challengeId, 3, step3Final);
  
  // Store speed challenge tokens
  db.prepare(
    `INSERT INTO speed_tokens (challenge_id, token_a, token_b, token_c)
     VALUES (?, ?, ?, ?)`
  ).run(challengeId, speedTokenA, speedTokenB, speedTokenC);
  
  // Store dynamic challenge for validation
  db.prepare(
    `INSERT INTO dynamic_challenges (id, challenge_id, language, code, answer_line, answer_issue, answer_fix, bug_type, difficulty)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    dynamicChallenge.id,
    challengeId,
    dynamicChallenge.language,
    dynamicChallenge.code,
    dynamicChallenge.answer.line,
    dynamicChallenge.answer.issue,
    dynamicChallenge.answer.fix,
    dynamicChallenge.bugType,
    dynamicChallenge.difficulty
  );

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
    time_limit_seconds: timeLimit,
    reasoning_challenge: reasoningChallenge,
    dynamic_challenge: dynamicChallenge,
    ip_address: ipAddress,
    fingerprint,
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
  
  // Get static reasoning challenge (for backwards compat)
  const reasoningChallenge = reasoningChallenges.find(
    (c) => c.id === tasksData.reasoningChallengeId
  );
  
  // Get dynamic challenge if exists
  const dynamicRow = db.prepare(
    "SELECT * FROM dynamic_challenges WHERE challenge_id = ?"
  ).get(challengeId) as any;
  
  let dynamicChallenge: DynamicChallenge | undefined;
  if (dynamicRow) {
    dynamicChallenge = {
      id: dynamicRow.id,
      language: dynamicRow.language,
      code: dynamicRow.code,
      answer: {
        line: dynamicRow.answer_line,
        issue: dynamicRow.answer_issue,
        fix: dynamicRow.answer_fix,
      },
      difficulty: dynamicRow.difficulty,
      bugType: dynamicRow.bug_type,
      generatedAt: dynamicRow.created_at,
    };
  }

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
    time_limit_seconds: tasksData.timeLimit || 30,
    reasoning_challenge: reasoningChallenge,
    dynamic_challenge: dynamicChallenge,
    ip_address: row.ip_address,
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

/**
 * Get speed token for a challenge
 */
export function getSpeedToken(
  challengeId: string,
  endpoint: "a" | "b" | "c"
): { token: string } | null {
  const db = getDb();
  const row = db.prepare(
    "SELECT * FROM speed_tokens WHERE challenge_id = ?"
  ).get(challengeId) as any;
  
  if (!row) return null;
  
  const tokenKey = `token_${endpoint}` as keyof typeof row;
  const fetchKey = `fetch_${endpoint}_at` as keyof typeof row;
  
  // Record fetch time
  db.prepare(
    `UPDATE speed_tokens SET fetch_${endpoint}_at = datetime('now') WHERE challenge_id = ?`
  ).run(challengeId);
  
  return { token: row[tokenKey] };
}

/**
 * Validate speed challenge - tokens must be fetched in parallel (within 2 seconds of each other)
 */
export function validateSpeedChallenge(
  challengeId: string,
  submittedCombined: string
): { passed: boolean; error?: string; wasParallel: boolean } {
  const db = getDb();
  const row = db.prepare(
    "SELECT * FROM speed_tokens WHERE challenge_id = ?"
  ).get(challengeId) as any;
  
  if (!row) {
    return { passed: false, error: "Speed challenge not found", wasParallel: false };
  }
  
  // Check if all tokens were fetched
  if (!row.fetch_a_at || !row.fetch_b_at || !row.fetch_c_at) {
    return { 
      passed: false, 
      error: "Not all speed endpoints were fetched",
      wasParallel: false,
    };
  }
  
  // Check if combined value is correct
  const expectedCombined = `${row.token_a}${row.token_b}${row.token_c}`;
  if (submittedCombined !== expectedCombined) {
    return { 
      passed: false, 
      error: "Incorrect combined token value",
      wasParallel: false,
    };
  }
  
  // Check if fetches were parallel (within 2 seconds of each other)
  const fetchTimes = [
    new Date(row.fetch_a_at).getTime(),
    new Date(row.fetch_b_at).getTime(),
    new Date(row.fetch_c_at).getTime(),
  ];
  
  const maxDiff = Math.max(...fetchTimes) - Math.min(...fetchTimes);
  const wasParallel = maxDiff < 2000; // 2 second tolerance
  
  if (!wasParallel) {
    return {
      passed: false,
      error: `Speed endpoints must be fetched in parallel. Your fetches were ${Math.round(maxDiff / 1000)}s apart.`,
      wasParallel: false,
    };
  }
  
  return { passed: true, wasParallel: true };
}

export { validateReasoningAnswer, validateBio, checkBioUniqueness, validateDynamicAnswer };
