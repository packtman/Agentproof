/**
 * Claim Routes - Tweet-based human-in-the-loop verification
 * 
 * Flow:
 * 1. User visits claim page with their claim token
 * 2. We show them a verification code to tweet
 * 3. User posts tweet with the code
 * 4. User pastes the tweet URL back
 * 5. We verify and link their X account to the agent
 * 
 * This approach doesn't require OAuth setup - just public tweet verification.
 */

import { Hono } from "hono";
import { getDb } from "../db/index.js";
import * as crypto from "crypto";

const claim = new Hono();

// Helper to generate random verification code
function generateVerificationCode(): string {
  return crypto.randomBytes(4).toString("hex").toUpperCase(); // 8 char hex code
}

// Get base URL from env
function getBaseUrl(): string {
  return process.env.BASE_URL || "https://knowyourclaw.com";
}

// Extract Twitter username from tweet URL
function extractTwitterUsername(url: string): string | null {
  // Match both twitter.com and x.com URLs
  // https://twitter.com/username/status/123456
  // https://x.com/username/status/123456
  const patterns = [
    /https?:\/\/(www\.)?(twitter\.com|x\.com)\/([a-zA-Z0-9_]+)\/status\/(\d+)/,
    /https?:\/\/(www\.)?(twitter\.com|x\.com)\/([a-zA-Z0-9_]+)\/statuses\/(\d+)/,
  ];
  
  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) {
      return match[3]; // username is in group 3
    }
  }
  return null;
}

// Extract tweet ID from URL
function extractTweetId(url: string): string | null {
  const patterns = [
    /https?:\/\/(www\.)?(twitter\.com|x\.com)\/[a-zA-Z0-9_]+\/status\/(\d+)/,
    /https?:\/\/(www\.)?(twitter\.com|x\.com)\/[a-zA-Z0-9_]+\/statuses\/(\d+)/,
  ];
  
  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) {
      return match[3]; // tweet ID is in group 3
    }
  }
  return null;
}

interface AgentRow {
  id: string;
  name: string;
  description: string | null;
  public_key: string;
  status: string;
  capabilities: string | null;
  model_family: string | null;
  framework: string | null;
  claim_token: string | null;
  claim_expires_at: string | null;
  owner_id: string | null;
  verified_at: string;
  created_at: string;
}

interface OwnerRow {
  id: string;
  provider: string;
  provider_id: string;
  handle: string;
  display_name: string | null;
  avatar_url: string | null;
}

interface ClaimVerificationRow {
  id: string;
  claim_token: string;
  verification_code: string;
  created_at: string;
  expires_at: string;
}

/**
 * GET /api/v1/claim/:token
 * Get claim information for an agent (used by ClaimPage)
 * Returns verification code for tweeting
 */
claim.get("/:token", async (c) => {
  const claimToken = c.req.param("token");
  
  // Don't match auth routes (legacy, keeping for safety)
  if (claimToken === "auth") {
    return c.notFound();
  }
  
  const db = getDb();

  // Find agent by claim token
  const agent = db.prepare(
    "SELECT * FROM agents WHERE claim_token = ?"
  ).get(claimToken) as AgentRow | undefined;

  if (!agent) {
    return c.json({
      success: false,
      error: "Invalid or expired claim link",
      hint: "This link may have already been used or expired. Claim links are valid for 7 days after verification.",
    }, 404);
  }

  // Check if claim has expired
  if (agent.claim_expires_at && new Date(agent.claim_expires_at) < new Date()) {
    return c.json({
      success: false,
      error: "Claim link has expired",
      hint: "The agent can request a new claim link by re-verifying.",
    }, 410);
  }

  // Check if already claimed
  let owner: OwnerRow | undefined;
  if (agent.owner_id) {
    owner = db.prepare(
      "SELECT * FROM owners WHERE id = ?"
    ).get(agent.owner_id) as OwnerRow | undefined;
  }

  // Generate or retrieve verification code for this claim
  let verification = db.prepare(
    "SELECT * FROM oauth_states WHERE claim_token = ? AND expires_at > datetime('now')"
  ).get(claimToken) as ClaimVerificationRow | undefined;

  if (!verification) {
    // Create new verification code
    const code = generateVerificationCode();
    const id = crypto.randomBytes(16).toString("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours

    db.prepare(
      `INSERT INTO oauth_states (id, provider, claim_token, code_verifier, expires_at)
       VALUES (?, 'twitter', ?, ?, ?)`
    ).run(id, claimToken, code, expiresAt);

    verification = {
      id,
      claim_token: claimToken,
      verification_code: code,
      created_at: new Date().toISOString(),
      expires_at: expiresAt,
    };
  }

  // Build the tweet text
  const tweetText = `I'm claiming "${agent.name}" on @KnowYourClaw 🪪\n\nVerify: ${verification.verification_code || (verification as any).code_verifier}\n\n${getBaseUrl()}/a/${encodeURIComponent(agent.name)}`;
  const tweetIntentUrl = `https://twitter.com/intent/tweet?text=${encodeURIComponent(tweetText)}`;

  return c.json({
    success: true,
    agent: {
      id: agent.id,
      name: agent.name,
      description: agent.description,
      status: agent.status,
      verified_at: agent.verified_at,
      capabilities: agent.capabilities ? JSON.parse(agent.capabilities) : [],
      model_family: agent.model_family,
      framework: agent.framework,
    },
    claim_expires_at: agent.claim_expires_at,
    already_claimed: !!agent.owner_id,
    owner: owner ? {
      provider: owner.provider,
      handle: owner.handle,
      display_name: owner.display_name,
    } : undefined,
    // Tweet verification data
    verification: !agent.owner_id ? {
      code: verification.verification_code || (verification as any).code_verifier,
      tweet_text: tweetText,
      tweet_intent_url: tweetIntentUrl,
      expires_at: verification.expires_at,
    } : undefined,
  });
});

/**
 * POST /api/v1/claim/:token
 * Complete the claim by submitting tweet URL
 */
claim.post("/:token", async (c) => {
  const claimToken = c.req.param("token");
  const db = getDb();

  try {
    const body = await c.req.json();
    const { tweet_url } = body;

    if (!tweet_url) {
      return c.json({
        success: false,
        error: "Missing tweet_url",
        hint: "Please provide the URL of your verification tweet",
      }, 400);
    }

    // Extract username from tweet URL
    const username = extractTwitterUsername(tweet_url);
    const tweetId = extractTweetId(tweet_url);

    if (!username || !tweetId) {
      return c.json({
        success: false,
        error: "Invalid tweet URL",
        hint: "Please provide a valid X/Twitter tweet URL (e.g., https://x.com/username/status/123456)",
      }, 400);
    }

    // Find agent by claim token
    const agent = db.prepare(
      "SELECT * FROM agents WHERE claim_token = ?"
    ).get(claimToken) as AgentRow | undefined;

    if (!agent) {
      return c.json({
        success: false,
        error: "Invalid or expired claim token",
      }, 404);
    }

    // Check expiry
    if (agent.claim_expires_at && new Date(agent.claim_expires_at) < new Date()) {
      return c.json({
        success: false,
        error: "Claim link has expired",
      }, 410);
    }

    // Check if already claimed
    if (agent.owner_id) {
      return c.json({
        success: false,
        error: "Agent has already been claimed",
      }, 400);
    }

    // Verify we have a verification code for this claim
    const verification = db.prepare(
      "SELECT * FROM oauth_states WHERE claim_token = ? AND expires_at > datetime('now')"
    ).get(claimToken) as ClaimVerificationRow | undefined;

    if (!verification) {
      return c.json({
        success: false,
        error: "Verification code expired",
        hint: "Please refresh the page to get a new verification code",
      }, 400);
    }

    // Check if this Twitter account already claimed another agent
    const existingOwner = db.prepare(
      "SELECT * FROM owners WHERE provider = 'twitter' AND handle = ?"
    ).get(username.toLowerCase()) as OwnerRow | undefined;

    if (existingOwner) {
      const existingAgent = db.prepare(
        "SELECT name FROM agents WHERE owner_id = ?"
      ).get(existingOwner.id) as { name: string } | undefined;

      if (existingAgent) {
        return c.json({
          success: false,
          error: `@${username} has already claimed agent "${existingAgent.name}"`,
          hint: "Each X/Twitter account can only claim one agent.",
        }, 400);
      }
    }

    // Create or update owner record
    let ownerId: string;
    if (existingOwner) {
      ownerId = existingOwner.id;
      db.prepare(
        `UPDATE owners SET updated_at = datetime('now') WHERE id = ?`
      ).run(ownerId);
    } else {
      ownerId = `own_${Date.now().toString(36)}${crypto.randomBytes(3).toString("hex")}`;
      db.prepare(
        `INSERT INTO owners (id, provider, provider_id, handle, display_name, avatar_url)
         VALUES (?, 'twitter', ?, ?, NULL, NULL)`
      ).run(ownerId, tweetId, username.toLowerCase()); // Using tweet ID as provider_id for uniqueness
    }

    // Update agent with owner and clear claim token
    db.prepare(
      `UPDATE agents SET owner_id = ?, claim_token = NULL, updated_at = datetime('now')
       WHERE id = ?`
    ).run(ownerId, agent.id);

    // Clean up verification code
    db.prepare("DELETE FROM oauth_states WHERE claim_token = ?").run(claimToken);

    return c.json({
      success: true,
      message: "Agent claimed successfully!",
      agent: {
        id: agent.id,
        name: agent.name,
      },
      owner: {
        provider: "twitter",
        handle: username,
      },
      profile_url: `${getBaseUrl()}/a/${encodeURIComponent(agent.name)}`,
      tweet_url: tweet_url,
    });

  } catch (error) {
    console.error("Claim error:", error);
    return c.json({
      success: false,
      error: "Failed to process claim",
    }, 500);
  }
});

export default claim;
