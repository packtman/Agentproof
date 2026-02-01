/**
 * AgentProof API Application
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { prettyJSON } from "hono/pretty-json";
import * as fs from "fs";
import * as path from "path";

import challenges from "./routes/challenges.js";
import submit from "./routes/submit.js";
import verify from "./routes/verify.js";
import platforms from "./routes/platforms.js";
import publicRoutes from "./routes/public.js";
import claim from "./routes/claim.js";

const app = new Hono();

// Middleware
app.use("*", cors());
app.use("*", logger());
app.use("*", prettyJSON());

// Health check
app.get("/health", (c) => {
  return c.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Serve markdown files
app.get("/verify.md", (c) => {
  try {
    const filePath = path.join(process.cwd(), "public", "verify.md");
    const content = fs.readFileSync(filePath, "utf-8");
    return c.text(content);
  } catch (error) {
    return c.text("# verify.md not found", 404);
  }
});

app.get("/skill.md", (c) => {
  try {
    const filePath = path.join(process.cwd(), "public", "skill.md");
    const content = fs.readFileSync(filePath, "utf-8");
    return c.text(content);
  } catch (error) {
    return c.text("# skill.md not found", 404);
  }
});

app.get("/prove-yourself.md", (c) => {
  try {
    const filePath = path.join(process.cwd(), "public", "prove-yourself.md");
    const content = fs.readFileSync(filePath, "utf-8");
    return c.text(content);
  } catch (error) {
    return c.text("# prove-yourself.md not found", 404);
  }
});

// API routes
app.route("/api/v1/challenges", challenges);
app.route("/api/v1/challenges", submit); // Submit is under challenges/:id/submit
app.route("/api/v1/verify", verify);
app.route("/api/v1", verify); // Also mount agents under /api/v1/agents
app.route("/api/v1/platforms", platforms);
app.route("/api/v1/public", publicRoutes);
app.route("/api/v1/claim", claim); // Claim routes for human-in-the-loop verification

// Serve static files from web-dist (React UI)
const webDistPath = path.join(process.cwd(), "web-dist");
const hasWebDist = fs.existsSync(webDistPath);

// Serve static assets (js, css, images)
app.get("/assets/*", (c) => {
  if (!hasWebDist) return c.notFound();
  const filePath = path.join(webDistPath, c.req.path);
  try {
    const content = fs.readFileSync(filePath);
    const ext = path.extname(filePath);
    const mimeTypes: Record<string, string> = {
      ".js": "application/javascript",
      ".css": "text/css",
      ".svg": "image/svg+xml",
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".ico": "image/x-icon",
    };
    return c.body(content, 200, { "Content-Type": mimeTypes[ext] || "application/octet-stream" });
  } catch {
    return c.notFound();
  }
});

// Root route - serve UI or API info
app.get("/", (c) => {
  // If UI is available and request accepts HTML, serve UI
  const acceptsHtml = c.req.header("Accept")?.includes("text/html");
  
  if (hasWebDist && acceptsHtml) {
    try {
      const html = fs.readFileSync(path.join(webDistPath, "index.html"), "utf-8");
      return c.html(html);
    } catch {
      // Fall through to JSON
    }
  }
  
  // Otherwise return API info (for curl, agents, etc.)
  const baseUrl = process.env.BASE_URL || "https://knowyourclaw.com";
  return c.json({
    name: "KnowYourClaw",
    version: "0.1.0",
    description: "Know Your Claw - Universal agent verification service",
    docs: `${baseUrl}/verify.md`,
    ui: hasWebDist ? `${baseUrl}/` : "Not deployed",
    endpoints: {
      challenges: {
        create: "POST /api/v1/challenges",
        get: "GET /api/v1/challenges/:id",
        submit: "POST /api/v1/challenges/:id/submit",
      },
      platforms: {
        register: "POST /api/v1/platforms/register",
      },
      verify: {
        token: "POST /api/v1/verify",
        agent: "GET /api/v1/agents/:id",
      },
      public: {
        stats: "GET /api/v1/public/stats",
        agents: "GET /api/v1/public/agents",
      },
    },
    links: {
      github: "https://github.com/packtman/KnowYourClaw",
      docs: `${baseUrl}/verify.md`,
    },
  });
});

// SPA fallback - serve index.html for client-side routing
app.get("*", (c) => {
  // Skip API routes and static files
  if (c.req.path.startsWith("/api/") || c.req.path.includes(".")) {
    return c.notFound();
  }
  
  if (hasWebDist) {
    try {
      const html = fs.readFileSync(path.join(webDistPath, "index.html"), "utf-8");
      return c.html(html);
    } catch {
      return c.notFound();
    }
  }
  return c.notFound();
});

// 404 handler for API routes
app.notFound((c) => {
  if (c.req.path.startsWith("/api/")) {
    return c.json({ success: false, error: "Not found" }, 404);
  }
  return c.json({ success: false, error: "Not found" }, 404);
});

// Error handler
app.onError((err, c) => {
  console.error("Server error:", err);
  return c.json(
    { success: false, error: "Internal server error" },
    500
  );
});

export default app;
