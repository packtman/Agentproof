/**
 * Verification Routes (for platforms)
 * POST /api/v1/verify - Verify an agent's proof token
 * GET /api/v1/agents/:id - Get agent info
 */

import { Hono } from "hono";
import { z } from "zod";
import { verifyProofToken } from "../lib/jwt.js";
import { getAgent, recordVerification, getProof } from "../services/proof.service.js";
import {
  validateApiKey,
  incrementVerificationCount,
  checkRateLimit,
} from "../services/platform.service.js";

const verify = new Hono();

// Validation schemas
const verifySchema = z.object({
  token: z.string(),
});

/**
 * Middleware to validate platform API key
 */
async function platformAuth(c: any, next: () => Promise<void>) {
  const apiKey = c.req.header("X-API-Key");

  if (!apiKey) {
    return c.json(
      { success: false, error: "Missing API key. Include X-API-Key header." },
      401
    );
  }

  const platform = await validateApiKey(apiKey);

  if (!platform) {
    return c.json({ success: false, error: "Invalid API key" }, 401);
  }

  if (!checkRateLimit(platform)) {
    return c.json({ success: false, error: "Rate limit exceeded" }, 429);
  }

  // Attach platform to context
  c.set("platform", platform);
  await next();
}

/**
 * POST /api/v1/verify
 * Verify an agent's proof token
 */
verify.post("/", platformAuth, async (c) => {
  const platform = (c as any).get("platform") as { id: string; name: string };

  try {
    const body = await c.req.json();
    const data = verifySchema.parse(body);

    // Verify the JWT token
    const result = await verifyProofToken(data.token);

    if (!result.valid || !result.payload) {
      return c.json({
        success: false,
        valid: false,
        error: result.error || "Invalid token",
      });
    }

    // Get agent info
    const agent = getAgent(result.payload.sub);

    if (!agent) {
      return c.json({
        success: false,
        valid: false,
        error: "Agent not found",
      });
    }

    // Check agent status
    if (agent.status !== "verified") {
      return c.json({
        success: false,
        valid: false,
        error: `Agent status is ${agent.status}`,
      });
    }

    // Record the verification
    recordVerification(result.payload.jti, platform.id);
    incrementVerificationCount(platform.id);

    return c.json({
      success: true,
      valid: true,
      agent: {
        id: agent.id,
        name: agent.name,
        description: agent.description,
        status: agent.status,
        verified_at: agent.verified_at,
        capabilities: agent.capabilities,
        model_family: agent.model_family,
        framework: agent.framework,
      },
      proof: {
        id: result.payload.jti,
        issued_at: new Date(result.payload.iat * 1000).toISOString(),
        expires_at: new Date(result.payload.exp * 1000).toISOString(),
        challenge_difficulty: result.payload.agp.difficulty,
        tasks_passed: result.payload.agp.tasks_passed,
      },
      owner: {
        claimed: !!agent.owner_id,
        // Include owner details if claimed (would need to fetch)
      },
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(
        { success: false, error: "Validation error", details: error.errors },
        400
      );
    }
    console.error("Verification error:", error);
    return c.json({ success: false, error: "Verification failed" }, 500);
  }
});

/**
 * GET /api/v1/agents/:id
 * Get public agent information
 */
verify.get("/agents/:id", async (c) => {
  const agentId = c.req.param("id");
  const agent = getAgent(agentId);

  if (!agent) {
    return c.json({ success: false, error: "Agent not found" }, 404);
  }

  const baseUrl = process.env.BASE_URL || "https://knowyourclaw.com";

  return c.json({
    success: true,
    agent: {
      id: agent.id,
      name: agent.name,
      description: agent.description,
      status: agent.status,
      verified_at: agent.verified_at,
      capabilities: agent.capabilities,
      model_family: agent.model_family,
      framework: agent.framework,
      owner: {
        claimed: !!agent.owner_id,
      },
      badge_url: `${baseUrl}/badge/${agent.id}.svg`,
      profile_url: `${baseUrl}/a/${encodeURIComponent(agent.name)}`,
    },
  });
});

export default verify;
