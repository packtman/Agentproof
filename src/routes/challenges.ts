/**
 * Challenge Routes
 * POST /api/v1/challenges - Create new challenge
 * GET /api/v1/challenges/:id - Get challenge details
 * GET /api/v1/challenges/:id/step1,2,3 - Tool-use challenge steps
 * POST /api/v1/challenges/:id/step2 - Submit step2 value
 */

import { Hono } from "hono";
import { z } from "zod";
import {
  createChallenge,
  getChallenge,
  getToolUseStep,
  completeToolUseStep,
} from "../services/challenge.service.js";
import { generateToken } from "../lib/crypto.js";

const challenges = new Hono();

// Validation schemas
const createChallengeSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(1000).optional(),
  capabilities: z.array(z.string()).optional().default([]),
  model_family: z.string().optional(),
  framework: z.string().optional(),
  difficulty: z.enum(["easy", "standard", "hard"]).optional().default("standard"),
});

/**
 * POST /api/v1/challenges
 * Create a new verification challenge
 */
challenges.post("/", async (c) => {
  try {
    const body = await c.req.json();
    const data = createChallengeSchema.parse(body);

    const challenge = createChallenge(
      data.name,
      data.description || "",
      data.capabilities,
      data.model_family,
      data.framework,
      data.difficulty
    );

    return c.json({
      success: true,
      challenge_id: challenge.id,
      agent_name: challenge.agent_name,
      expires_at: challenge.expires_at,
      expires_in_seconds: Math.floor(
        (new Date(challenge.expires_at).getTime() - Date.now()) / 1000
      ),
      tasks: challenge.tasks.map((task) => ({
        type: task.type,
        prompt: task.prompt,
      })),
      submit_url: `${process.env.BASE_URL || "https://agentdmv.com"}/api/v1/challenges/${challenge.id}/submit`,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(
        { success: false, error: "Validation error", details: error.errors },
        400
      );
    }
    console.error("Challenge creation error:", error);
    return c.json({ success: false, error: "Failed to create challenge" }, 500);
  }
});

/**
 * GET /api/v1/challenges/:id
 * Get challenge details (without answers)
 */
challenges.get("/:id", async (c) => {
  const challengeId = c.req.param("id");
  const challenge = getChallenge(challengeId);

  if (!challenge) {
    return c.json({ success: false, error: "Challenge not found" }, 404);
  }

  // Check if expired
  if (new Date(challenge.expires_at) < new Date()) {
    return c.json({ success: false, error: "Challenge expired" }, 410);
  }

  return c.json({
    success: true,
    challenge: {
      id: challenge.id,
      status: challenge.status,
      expires_at: challenge.expires_at,
      tasks: challenge.tasks.map((task) => ({
        type: task.type,
        prompt: task.prompt,
      })),
    },
  });
});

/**
 * GET /api/v1/challenges/:id/step1
 * Tool-use challenge step 1
 */
challenges.get("/:id/step1", async (c) => {
  const challengeId = c.req.param("id");
  const challenge = getChallenge(challengeId);

  if (!challenge) {
    return c.json({ success: false, error: "Challenge not found" }, 404);
  }

  if (new Date(challenge.expires_at) < new Date()) {
    return c.json({ success: false, error: "Challenge expired" }, 410);
  }

  const step = getToolUseStep(challengeId, 1);
  if (!step) {
    return c.json({ success: false, error: "Step not found" }, 404);
  }

  // Mark step 1 as accessed
  completeToolUseStep(challengeId, 1, "accessed");

  return c.json({
    success: true,
    value: step.expectedValue,
    next_step: "POST this value to /step2",
    hint: "Send JSON body: {\"value\": \"" + step.expectedValue + "\"}",
  });
});

/**
 * POST /api/v1/challenges/:id/step2
 * Tool-use challenge step 2
 */
challenges.post("/:id/step2", async (c) => {
  const challengeId = c.req.param("id");
  const challenge = getChallenge(challengeId);

  if (!challenge) {
    return c.json({ success: false, error: "Challenge not found" }, 404);
  }

  if (new Date(challenge.expires_at) < new Date()) {
    return c.json({ success: false, error: "Challenge expired" }, 410);
  }

  try {
    const body = await c.req.json();
    const { value } = body;

    // Verify step 1 was completed and value matches
    const step1 = getToolUseStep(challengeId, 1);
    if (!step1 || step1.expectedValue !== value) {
      return c.json({ success: false, error: "Invalid value from step 1" }, 400);
    }

    // Get step 2 token
    const step2 = getToolUseStep(challengeId, 2);
    if (!step2) {
      return c.json({ success: false, error: "Step not found" }, 404);
    }

    // Mark step 2 as completed with the received value
    completeToolUseStep(challengeId, 2, value);

    return c.json({
      success: true,
      token: step2.expectedValue,
      next_step: "GET /step3 with this token as query param",
      hint: `GET /step3?token=${step2.expectedValue}`,
    });
  } catch (error) {
    return c.json({ success: false, error: "Invalid request body" }, 400);
  }
});

/**
 * GET /api/v1/challenges/:id/step3
 * Tool-use challenge step 3
 */
challenges.get("/:id/step3", async (c) => {
  const challengeId = c.req.param("id");
  const token = c.req.query("token");

  const challenge = getChallenge(challengeId);

  if (!challenge) {
    return c.json({ success: false, error: "Challenge not found" }, 404);
  }

  if (new Date(challenge.expires_at) < new Date()) {
    return c.json({ success: false, error: "Challenge expired" }, 410);
  }

  // Verify token from step 2
  const step2 = getToolUseStep(challengeId, 2);
  if (!step2 || step2.expectedValue !== token) {
    return c.json({ success: false, error: "Invalid token from step 2" }, 400);
  }

  // Get final value
  const step3 = getToolUseStep(challengeId, 3);
  if (!step3) {
    return c.json({ success: false, error: "Step not found" }, 404);
  }

  // Mark step 3 as completed
  completeToolUseStep(challengeId, 3, step3.expectedValue);

  return c.json({
    success: true,
    final_value: step3.expectedValue,
    message: "Tool-use challenge completed! Include this final_value in your submission.",
  });
});

export default challenges;
