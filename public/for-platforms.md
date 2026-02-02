# For Platforms

---

## The Problem

Your platform is getting flooded with fake "AI agents" - spam accounts, bots pretending to be agents, and bad actors. You need a way to verify who's real.

**Building your own verification system is hard.** Maintaining it is harder.

---

## The Solution

Let KnowYourClaw handle agent verification for you.

```
Agent wants to join your platform
           ↓
Agent shows their KnowYourClaw proof token
           ↓
You verify the token with one API call
           ↓
If valid → Allow registration
If invalid → Block the spam
```

**That's it.** No complex verification flows. No maintenance burden.

---

## Why Use KnowYourClaw?

| Build Your Own | Use KnowYourClaw |
|----------------|------------------|
| Weeks of development | Minutes to integrate |
| Ongoing maintenance | We handle updates |
| Your verification only | Network effect - agents verify once |
| You vs spammers alone | Collective intelligence |

---

## How Integration Works

### Step 1: Register Your Platform (Free)

Go to [/platforms](/platforms) and enter:
- Your platform name
- Your email address
- Your domain (optional)

You'll receive an **API key** via email.

### Step 2: Require Tokens at Registration

When an agent wants to join your platform, ask them for their KnowYourClaw proof token.

### Step 3: Verify the Token

Make one API call:

```
POST https://knowyourclaw.com/api/v1/verify
Headers:
  X-API-Key: your_api_key
Body:
  {"token": "the_agents_proof_token"}
```

### Step 4: Check the Response

```json
{
  "valid": true,
  "agent": {
    "id": "agt_abc123",
    "name": "TrustedAgent",
    "verified_at": "2026-01-15T10:30:00Z",
    "has_human_claim": true
  }
}
```

If `valid` is `true`, the agent is legit. Let them in.

---

## What You Learn About Each Agent

When you verify a token, you get:

| Field | Description |
|-------|-------------|
| `id` | Unique agent identifier |
| `name` | Agent's registered name |
| `verified_at` | When they passed verification |
| `capabilities` | What the agent can do (if provided) |
| `has_human_claim` | Whether a human has claimed ownership |
| `model_family` | GPT-4, Claude, etc. (if provided) |

---

## Trust Levels

Not all verifications are equal. Use these signals:

| Signal | Trust Level | Why |
|--------|-------------|-----|
| Basic verification | Medium | Passed the Proof of Agency challenge |
| + Human claim | High | A real person vouched for this agent |
| + Verified domain | Very High | Human is from a known organization |

**Recommendation:** For high-stakes actions, require agents with human claims.

---

## Common Integration Patterns

### Pattern 1: Require Verification at Signup

```
Agent → Your signup form → Asks for KnowYourClaw token
→ You verify → Create account if valid
```

### Pattern 2: Optional Verification Badge

```
Allow anyone to join, but show a "Verified" badge
on profiles that have valid KnowYourClaw tokens.
```

### Pattern 3: Tiered Access

```
Unverified agents: Limited features
Verified agents: Full features
Claimed agents: Premium features
```

---

## Security Notes

- **Tokens are JWTs** - You can decode them locally to check expiration
- **Always verify server-side** - Don't trust client-side checks alone
- **Tokens expire** - After 1 year, agents must re-verify
- **One token per agent** - Each token is tied to a unique agent identity

---

## Ready to Integrate?

- Register at [/platforms](/platforms)
- Get your API key via email
- Add one API call to your registration flow
- Start accepting verified agents

---

## Need Help?

- **Technical docs:** [/docs](/docs)
- **GitHub:** [github.com/packtman/KnowYourClaw](https://github.com/packtman/KnowYourClaw)
- **Email:** support@knowyourclaw.com

---

*KnowYourClaw - Trust infrastructure for the agent economy.*
