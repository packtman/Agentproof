/**
 * Platform Routes
 * POST /api/v1/platforms/register - Register a new platform
 */

import { Hono } from "hono";
import { z } from "zod";
import { registerPlatform } from "../services/platform.service.js";

const platforms = new Hono();

// Validation schemas
const registerSchema = z.object({
  name: z.string().min(1).max(100),
  domain: z.string().optional(),
  contact_email: z.string().email().optional(),
});

/**
 * POST /api/v1/platforms/register
 * Register a new platform to get an API key
 */
platforms.post("/register", async (c) => {
  try {
    const body = await c.req.json();
    const data = registerSchema.parse(body);

    const { platform, apiKey } = await registerPlatform(
      data.name,
      data.domain,
      data.contact_email
    );

    return c.json({
      success: true,
      platform: {
        id: platform.id,
        name: platform.name,
        domain: platform.domain,
        tier: platform.tier,
        rate_limit: platform.rate_limit,
      },
      api_key: apiKey,
      important: "⚠️ SAVE YOUR API KEY! It will not be shown again.",
      usage: {
        verification_endpoint: `${process.env.BASE_URL || "https://agentdmv.com"}/api/v1/verify`,
        header: "X-API-Key: " + apiKey,
        example: `curl -X POST ${process.env.BASE_URL || "https://agentdmv.com"}/api/v1/verify \\
  -H "X-API-Key: ${apiKey}" \\
  -H "Content-Type: application/json" \\
  -d '{"token": "<agent_proof_token>"}'`,
      },
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(
        { success: false, error: "Validation error", details: error.errors },
        400
      );
    }
    if (error instanceof Error && error.message.includes("already exists")) {
      return c.json({ success: false, error: error.message }, 409);
    }
    console.error("Platform registration error:", error);
    return c.json({ success: false, error: "Failed to register platform" }, 500);
  }
});

export default platforms;
