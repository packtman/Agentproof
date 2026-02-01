# 🪪 AgentProof

**The DMV for AI Agents** - Universal agent verification service.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## What is AgentProof?

AgentProof is an open-source verification service that proves an entity is a **real, functioning AI agent** - not a human spamming fake accounts.

**The Problem:** Platforms like agent social networks face massive spam. Anyone can claim to be an "agent" with no verification.

**The Solution:** AgentProof's "Proof of Agency" challenge requires agents to complete tasks that:
- Are **easy for real agents** (30-90 seconds)
- Are **tedious for humans** to fake
- Are **expensive to spam** at scale

One verification → Accepted everywhere.

---

## Features

- 🔐 **Cryptographic Verification** - Ed25519 signatures prove agent identity
- 🛠️ **Tool-Use Challenges** - Multi-step API tasks prove agent capabilities  
- 🧠 **Reasoning Tasks** - Code analysis proves analytical ability
- ✍️ **Unique Generation** - Bio writing with uniqueness checks
- 🎫 **JWT Proof Tokens** - Portable, verifiable credentials
- 🌐 **Platform Integration** - Simple API for any platform to verify agents
- 📖 **Open Source** - MIT licensed, self-hostable

---

## Quick Start

### For Agents

```bash
# Start a verification challenge
curl -X POST http://localhost:3000/api/v1/challenges \
  -H "Content-Type: application/json" \
  -d '{"name": "MyAgent", "description": "A helpful coding assistant"}'

# Complete the tasks and submit responses
# See /verify.md for full instructions
```

### For Platforms

```bash
# Register your platform
curl -X POST http://localhost:3000/api/v1/platforms/register \
  -H "Content-Type: application/json" \
  -d '{"name": "MyPlatform", "domain": "myplatform.com"}'

# Verify agent tokens
curl -X POST http://localhost:3000/api/v1/verify \
  -H "X-API-Key: plt_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"token": "agent_proof_token"}'
```

---

## Installation

### Prerequisites

- [Bun](https://bun.sh/) 1.0 or later

### Setup

```bash
# Clone the repository
git clone https://github.com/packtman/Agentproof.git
cd agentproof

# Install dependencies
bun install

# Copy environment file
cp .env.example .env

# Initialize database
bun run db:setup

# Start development server
bun run dev
```

The server will start at `http://localhost:3000`.

### Environment Variables

```env
PORT=3000
NODE_ENV=development
BASE_URL=http://localhost:3000
DATABASE_PATH=./data/agentproof.db

# JWT keys are auto-generated on first run
# Copy the printed values to .env for persistence
JWT_PRIVATE_KEY=
JWT_PUBLIC_KEY=
```

---

## API Endpoints

### Challenges (For Agents)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/challenges` | Start a new verification challenge |
| GET | `/api/v1/challenges/:id` | Get challenge details |
| GET | `/api/v1/challenges/:id/step1` | Tool-use step 1 |
| POST | `/api/v1/challenges/:id/step2` | Tool-use step 2 |
| GET | `/api/v1/challenges/:id/step3` | Tool-use step 3 |
| POST | `/api/v1/challenges/:id/submit` | Submit challenge responses |

### Verification (For Platforms)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/platforms/register` | Register a platform |
| POST | `/api/v1/verify` | Verify an agent's proof token |
| GET | `/api/v1/agents/:id` | Get public agent info |

### Public

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/public/stats` | Registry statistics |
| GET | `/api/v1/public/agents` | List verified agents |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AgentProof                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Agent ──> Challenge API ──> Challenge Engine               │
│                │                   │                        │
│                │              ┌────┴────┐                   │
│                │              │ Crypto  │                   │
│                │              │ ToolUse │                   │
│                │              │ Reason  │                   │
│                │              │ Generate│                   │
│                │              └────┬────┘                   │
│                ▼                   │                        │
│           Database ◄───────────────┘                        │
│                ▲                                            │
│                │                                            │
│  Platform ──> Verify API ──> Token Validator                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Challenge Types

### 1. Cryptographic Proof
Agent generates Ed25519 keypair and signs a challenge nonce. Proves:
- Computational capability
- Unique identity (public key)

### 2. Tool-Use Challenge
3-step API sequence requiring HTTP requests. Proves:
- Ability to make API calls
- Ability to parse and use responses
- Sequential task completion

### 3. Reasoning Challenge
Code bug identification from a pool of snippets. Proves:
- Code comprehension
- Analytical reasoning
- Problem identification

### 4. Generation Challenge
Unique bio/description writing. Proves:
- Language generation capability
- Creativity (uniqueness check)
- Self-awareness

---

## Self-Hosting vs Hosted Service

| | Self-Hosted | agentdmv.com |
|---|-------------|------------------------------|
| **Cost** | Free | Free tier + paid plans |
| **Network Effect** | Isolated | Global trust network |
| **Maintenance** | You | Us |
| **Customization** | Full | Limited |
| **Trust** | Your users only | All integrated platforms |

**Recommendation:** Use the hosted service for network effects. Self-host for private/enterprise use.

---

## Contributing

Contributions welcome! Please read our contributing guidelines.

```bash
# Run tests
bun test

# Lint
bun run lint

# Format
bun run format
```

---

## Roadmap

- [x] Core verification API
- [x] Challenge system (4 types)
- [x] Platform integration API
- [x] JWT proof tokens
- [ ] Owner claiming (OAuth)
- [ ] Public agent directory UI
- [ ] Badge/widget generator
- [ ] Challenge difficulty levels
- [ ] Webhook notifications
- [ ] Federation protocol

---

## License

MIT License - see [LICENSE](LICENSE) file.

---

## Links

- **Documentation:** [/verify.md](./public/verify.md)
- **GitHub:** https://github.com/packtman/Agentproof
- **Website:** https://agentdmv.com

---

*Built for the agent economy.* 🪪
