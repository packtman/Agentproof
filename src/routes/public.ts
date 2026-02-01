/**
 * Public Routes
 * GET /api/v1/public/stats - Public statistics
 * GET /api/v1/public/agents - List verified agents
 */

import { Hono } from "hono";
import { getDb } from "../db/index.js";

const publicRoutes = new Hono();

/**
 * GET /api/v1/public/stats
 * Get public statistics
 */
publicRoutes.get("/stats", async (c) => {
  const db = getDb();

  const totalAgents = db
    .prepare("SELECT COUNT(*) as count FROM agents")
    .get() as { count: number };

  const verifiedAgents = db
    .prepare("SELECT COUNT(*) as count FROM agents WHERE status = 'verified'")
    .get() as { count: number };

  const platformCount = db
    .prepare("SELECT COUNT(*) as count FROM platforms WHERE status = 'active'")
    .get() as { count: number };

  const verificationsToday = db
    .prepare(
      "SELECT COUNT(*) as count FROM challenges WHERE status = 'completed' AND date(completed_at) = date('now')"
    )
    .get() as { count: number };

  const recentAgents = db
    .prepare(
      "SELECT id, name, verified_at FROM agents WHERE status = 'verified' ORDER BY verified_at DESC LIMIT 5"
    )
    .all() as { id: string; name: string; verified_at: string }[];

  return c.json({
    success: true,
    stats: {
      total_agents: totalAgents.count,
      verified_agents: verifiedAgents.count,
      platforms_integrated: platformCount.count,
      verifications_today: verificationsToday.count,
    },
    recent_agents: recentAgents.map((a) => ({
      id: a.id,
      name: a.name,
      verified_at: a.verified_at,
    })),
  });
});

/**
 * GET /api/v1/public/agents
 * List verified agents (paginated)
 */
publicRoutes.get("/agents", async (c) => {
  const db = getDb();
  const page = parseInt(c.req.query("page") || "1", 10);
  const limit = Math.min(parseInt(c.req.query("limit") || "20", 10), 100);
  const offset = (page - 1) * limit;
  const sort = c.req.query("sort") || "recent";

  let orderBy = "verified_at DESC";
  if (sort === "name") orderBy = "name ASC";

  const agents = db
    .prepare(
      `SELECT id, name, description, status, capabilities, verified_at 
       FROM agents 
       WHERE status = 'verified' 
       ORDER BY ${orderBy} 
       LIMIT ? OFFSET ?`
    )
    .all(limit, offset) as any[];

  const total = db
    .prepare("SELECT COUNT(*) as count FROM agents WHERE status = 'verified'")
    .get() as { count: number };

  const baseUrl = process.env.BASE_URL || "https://agentdmv.com";

  return c.json({
    success: true,
    agents: agents.map((a) => ({
      id: a.id,
      name: a.name,
      description: a.description,
      capabilities: JSON.parse(a.capabilities || "[]"),
      verified_at: a.verified_at,
      profile_url: `${baseUrl}/a/${encodeURIComponent(a.name)}`,
      badge_url: `${baseUrl}/badge/${a.id}.svg`,
    })),
    pagination: {
      page,
      limit,
      total: total.count,
      total_pages: Math.ceil(total.count / limit),
    },
  });
});

export default publicRoutes;
