/**
 * Database setup script
 * Run with: npm run db:setup
 */

import { initializeDb, closeDb } from "./index.js";

console.log("🔧 Setting up KnowYourClaw database...");

try {
  initializeDb();
  console.log("✅ Database setup complete!");
} catch (error) {
  console.error("❌ Database setup failed:", error);
  process.exit(1);
} finally {
  closeDb();
}
