/**
 * Submit Route
 * POST /api/v1/challenges/:id/submit - Submit challenge responses
 */

import { Hono } from "hono";
import { z } from "zod";
import {
  getChallenge,
  updateChallengeStatus,
  validateToolUseCompletion,
  validateReasoningAnswer,
  validateBio,
  checkBioUniqueness,
  getExistingBios,
  storeBio,
} from "../services/challenge.service.js";
import { createVerifiedAgent } from "../services/proof.service.js";
import {
  verifyEd25519Signature,
  createSigningMessage,
} from "../lib/crypto.js";

const submit = new Hono();

// Validation schemas
const cryptoResponseSchema = z.object({
  type: z.literal("crypto"),
  public_key: z.string(),
  signature: z.string(),
});

const toolUseResponseSchema = z.object({
  type: z.literal("tool_use"),
  completed: z.boolean(),
  final_value: z.string(),
});

const reasoningResponseSchema = z.object({
  type: z.literal("reasoning"),
  line: z.number(),
  issue: z.string(),
  fix: z.string().optional(),
});

const generationResponseSchema = z.object({
  type: z.literal("generation"),
  bio: z.string(),
});

const submitSchema = z.object({
  responses: z.array(
    z.union([
      cryptoResponseSchema,
      toolUseResponseSchema,
      reasoningResponseSchema,
      generationResponseSchema,
    ])
  ),
});

interface TaskResult {
  type: string;
  passed: boolean;
  error?: string;
}

/**
 * POST /api/v1/challenges/:id/submit
 * Submit all challenge responses
 */
submit.post("/:id/submit", async (c) => {
  const challengeId = c.req.param("id");
  const challenge = getChallenge(challengeId);

  if (!challenge) {
    return c.json({ success: false, error: "Challenge not found" }, 404);
  }

  // Check if already completed
  if (challenge.status === "completed") {
    return c.json({ success: false, error: "Challenge already completed" }, 400);
  }

  // Check if expired
  if (new Date(challenge.expires_at) < new Date()) {
    updateChallengeStatus(challengeId, "expired");
    return c.json({ success: false, error: "Challenge expired" }, 410);
  }

  // Parse and validate request
  let data;
  try {
    const body = await c.req.json();
    data = submitSchema.parse(body);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(
        { success: false, error: "Validation error", details: error.errors },
        400
      );
    }
    return c.json({ success: false, error: "Invalid request body" }, 400);
  }

  // Track start time
  const startTime = Date.now();

  // Process each response
  const results: TaskResult[] = [];
  let publicKey: string | undefined;
  let bio: string | undefined;

  for (const response of data.responses) {
    switch (response.type) {
      case "crypto": {
        // Verify Ed25519 signature
        const message = createSigningMessage(challenge.nonce, challenge.agent_name);
        const valid = await verifyEd25519Signature(
          response.public_key,
          response.signature,
          message
        );

        if (valid) {
          publicKey = response.public_key;
          results.push({ type: "crypto", passed: true });
        } else {
          results.push({
            type: "crypto",
            passed: false,
            error: "Invalid signature",
          });
        }
        break;
      }

      case "tool_use": {
        // Verify tool-use completion
        const toolResult = validateToolUseCompletion(challengeId);
        
        if (toolResult.passed) {
          // Also verify the final value matches
          const step3 = await import("../services/challenge.service.js").then(
            (m) => m.getToolUseStep(challengeId, 3)
          );
          
          if (step3 && step3.expectedValue === response.final_value) {
            results.push({ type: "tool_use", passed: true });
          } else {
            results.push({
              type: "tool_use",
              passed: false,
              error: "Incorrect final value",
            });
          }
        } else {
          results.push({
            type: "tool_use",
            passed: false,
            error: toolResult.error,
          });
        }
        break;
      }

      case "reasoning": {
        // Validate reasoning answer
        if (!challenge.reasoning_challenge) {
          results.push({
            type: "reasoning",
            passed: false,
            error: "Reasoning challenge not found",
          });
          break;
        }

        const reasoningResult = validateReasoningAnswer(
          challenge.reasoning_challenge,
          {
            line: response.line,
            issue: response.issue,
            fix: response.fix,
          }
        );

        results.push({
          type: "reasoning",
          passed: reasoningResult.passed,
          error: reasoningResult.error,
        });
        break;
      }

      case "generation": {
        // Validate bio
        const bioValidation = validateBio(response.bio);
        if (!bioValidation.valid) {
          results.push({
            type: "generation",
            passed: false,
            error: bioValidation.error,
          });
          break;
        }

        // Check uniqueness
        const existingBios = getExistingBios();
        const uniquenessResult = checkBioUniqueness(response.bio, existingBios);

        if (!uniquenessResult.unique) {
          results.push({
            type: "generation",
            passed: false,
            error: `Bio too similar to existing agent (${Math.round(uniquenessResult.similarity! * 100)}% similar)`,
          });
        } else {
          bio = response.bio;
          results.push({ type: "generation", passed: true });
        }
        break;
      }
    }
  }

  // Calculate time taken
  const timeTakenMs = Date.now() - startTime;

  // Check results
  const passed = results.filter((r) => r.passed);
  const failed = results.filter((r) => !r.passed);

  if (failed.length > 0 || !publicKey) {
    updateChallengeStatus(challengeId, "failed", undefined, timeTakenMs);

    return c.json({
      success: false,
      status: "failed",
      passed: false,
      tasks_passed: passed.length,
      tasks_failed: failed.length,
      time_taken_ms: timeTakenMs,
      results,
      errors: failed.map((f) => ({ type: f.type, error: f.error })),
      retry_available: true,
      message: "One or more tasks failed. You can create a new challenge to retry.",
    });
  }

  // All tasks passed - create agent and proof
  try {
    const tasksPassed = results.map((r) => r.type);

    // Parse capabilities from challenge
    const capabilities: string[] = [];

    const { agent, proof } = await createVerifiedAgent(
      challenge.agent_name,
      challenge.agent_description,
      publicKey,
      capabilities,
      undefined, // model_family
      undefined, // framework
      challengeId,
      challenge.difficulty,
      tasksPassed,
      timeTakenMs
    );

    // Store bio
    if (bio) {
      storeBio(agent.id, bio);
    }

    // Update challenge status
    updateChallengeStatus(challengeId, "completed", agent.id, timeTakenMs);

    const baseUrl = process.env.BASE_URL || "https://agentdmv.com";

    return c.json({
      success: true,
      status: "completed",
      passed: true,
      tasks_passed: passed.length,
      tasks_failed: 0,
      time_taken_ms: timeTakenMs,
      results,
      proof: {
        id: proof.id,
        token: proof.token,
        expires_at: proof.expires_at,
      },
      agent: {
        id: agent.id,
        name: agent.name,
        status: agent.status,
        verified_at: agent.verified_at,
        claim_url: `${baseUrl}/claim/${agent.claim_token}`,
        profile_url: `${baseUrl}/a/${encodeURIComponent(agent.name)}`,
        badge_url: `${baseUrl}/badge/${agent.id}.svg`,
      },
      message: "Congratulations! You are now a verified agent. Share your claim_url with your human owner to complete the verification.",
    });
  } catch (error) {
    console.error("Agent creation error:", error);
    
    if (error instanceof Error && error.message.includes("already exists")) {
      return c.json({
        success: false,
        error: "An agent with this public key already exists",
        hint: "If this is your agent, you already have a proof token.",
      }, 409);
    }

    return c.json({ success: false, error: "Failed to create agent" }, 500);
  }
});

export default submit;
