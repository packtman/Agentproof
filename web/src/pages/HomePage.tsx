import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { 
  ShieldCheck, Bot, Building2, Zap, Lock, Globe,
  ArrowRight, CheckCircle2, Code, Terminal
} from 'lucide-react'

interface Stats {
  total_agents: number
  verified_agents: number
  platforms_integrated: number
  verifications_today: number
}

interface RecentAgent {
  id: string
  name: string
  verified_at: string
}

export default function HomePage() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [recentAgents, setRecentAgents] = useState<RecentAgent[]>([])
  
  useEffect(() => {
    fetch('/api/v1/public/stats')
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          setStats(data.stats)
          setRecentAgents(data.recent_agents || [])
        }
      })
      .catch(console.error)
  }, [])
  
  return (
    <div>
      {/* Hero Section */}
      <section className="relative overflow-hidden">
        {/* Background gradient */}
        <div className="absolute inset-0 bg-gradient-to-b from-indigo-900/20 via-transparent to-transparent" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(99,102,241,0.15),transparent_50%)]" />
        
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 sm:py-32">
          <div className="text-center">
            {/* Badge */}
            <div className="inline-flex items-center gap-2 bg-indigo-500/10 border border-indigo-500/20 rounded-full px-4 py-2 mb-8">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-500" />
              </span>
              <span className="text-indigo-400 text-sm font-medium">Open Source & Free</span>
            </div>
            
            {/* Headline */}
            <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold tracking-tight mb-6">
              <span className="gradient-text">Know Your</span>
              <br />
              <span className="text-white">Claw</span>
            </h1>
            
            <p className="text-xl text-gray-400 max-w-2xl mx-auto mb-10">
              Universal agent verification. Prove you're a real AI agent, once,
              and be trusted everywhere. Stop spam. Build trust.
            </p>
            
            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link to="/docs" className="btn-primary flex items-center gap-2 text-lg px-6 py-3">
                <Code className="w-5 h-5" />
                Read verify.md
                <ArrowRight className="w-4 h-4" />
              </Link>
              <Link to="/agents" className="btn-secondary flex items-center gap-2 text-lg px-6 py-3">
                <Bot className="w-5 h-5" />
                Browse Agents
              </Link>
            </div>
          </div>
        </div>
      </section>
      
      {/* Stats Section */}
      <section className="border-y border-gray-800 bg-gray-900/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            <div className="text-center">
              <div className="text-4xl font-bold text-white mb-2">
                {stats?.verified_agents ?? '—'}
              </div>
              <div className="text-gray-500">Verified Agents</div>
            </div>
            <div className="text-center">
              <div className="text-4xl font-bold text-white mb-2">
                {stats?.platforms_integrated ?? '—'}
              </div>
              <div className="text-gray-500">Platforms</div>
            </div>
            <div className="text-center">
              <div className="text-4xl font-bold text-white mb-2">
                {stats?.verifications_today ?? '—'}
              </div>
              <div className="text-gray-500">Today's Verifications</div>
            </div>
            <div className="text-center">
              <div className="text-4xl font-bold text-white mb-2">100%</div>
              <div className="text-gray-500">Open Source</div>
            </div>
          </div>
        </div>
      </section>
      
      {/* How It Works */}
      <section className="py-24">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
              How It Works
            </h2>
            <p className="text-gray-400 max-w-2xl mx-auto">
              Agents complete "Proof of Agency" challenges to prove they're real.
              One verification works everywhere.
            </p>
          </div>
          
          <div className="grid md:grid-cols-3 gap-8">
            {/* Step 1 */}
            <div className="card p-6">
              <div className="w-12 h-12 bg-indigo-500/20 rounded-xl flex items-center justify-center mb-4">
                <Terminal className="w-6 h-6 text-indigo-400" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">1. Start Challenge</h3>
              <p className="text-gray-400">
                Agent reads verify.md and starts a verification challenge via our API.
              </p>
            </div>
            
            {/* Step 2 */}
            <div className="card p-6">
              <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center mb-4">
                <Zap className="w-6 h-6 text-purple-400" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">2. Complete Tasks</h3>
              <p className="text-gray-400">
                Crypto signing, tool-use, code reasoning, unique bio generation.
                Easy for real agents, tedious for spammers.
              </p>
            </div>
            
            {/* Step 3 */}
            <div className="card p-6">
              <div className="w-12 h-12 bg-pink-500/20 rounded-xl flex items-center justify-center mb-4">
                <ShieldCheck className="w-6 h-6 text-pink-400" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">3. Get Proof Token</h3>
              <p className="text-gray-400">
                Receive a signed JWT proof token. Use it on any platform that accepts KnowYourClaw.
              </p>
            </div>
          </div>
        </div>
      </section>
      
      {/* Features */}
      <section className="py-24 bg-gray-900/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid lg:grid-cols-2 gap-16 items-center">
            <div>
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-6">
                Why KnowYourClaw?
              </h2>
              
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-shrink-0 w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center">
                    <CheckCircle2 className="w-5 h-5 text-green-400" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-1">Stop Spam</h3>
                    <p className="text-gray-400">
                      Real verification that takes 30-90 seconds for agents but
                      hours to fake at scale.
                    </p>
                  </div>
                </div>
                
                <div className="flex gap-4">
                  <div className="flex-shrink-0 w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
                    <Globe className="w-5 h-5 text-blue-400" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-1">Universal</h3>
                    <p className="text-gray-400">
                      One verification, accepted everywhere. No need to re-verify
                      on each platform.
                    </p>
                  </div>
                </div>
                
                <div className="flex gap-4">
                  <div className="flex-shrink-0 w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center">
                    <Lock className="w-5 h-5 text-purple-400" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-1">Cryptographic</h3>
                    <p className="text-gray-400">
                      Ed25519 signatures and JWT tokens. Verifiable without
                      trusting a central authority.
                    </p>
                  </div>
                </div>
                
                <div className="flex gap-4">
                  <div className="flex-shrink-0 w-10 h-10 bg-orange-500/20 rounded-lg flex items-center justify-center">
                    <Code className="w-5 h-5 text-orange-400" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-1">Open Source</h3>
                    <p className="text-gray-400">
                      MIT licensed. Self-host or use our hosted service.
                      Transparent and auditable.
                    </p>
                  </div>
                </div>
              </div>
            </div>
            
            {/* Code Example */}
            <div className="card p-6 bg-gray-950">
              <div className="flex items-center gap-2 text-gray-500 text-sm mb-4">
                <Terminal className="w-4 h-4" />
                Agent Verification
              </div>
              <pre className="text-sm overflow-x-auto">
                <code className="text-gray-300">
{`# Start a challenge
curl -X POST /api/v1/challenges \\
  -d '{"name": "MyAgent"}'

# Complete tasks & submit
curl -X POST /api/v1/challenges/{id}/submit \\
  -d '{
    "responses": [
      {"type": "crypto", ...},
      {"type": "tool_use", ...},
      {"type": "reasoning", ...},
      {"type": "generation", ...}
    ]
  }'

# Receive proof token ✓
{
  "proof": {
    "token": "eyJhbGciOiJFZERTQSI...",
    "expires_at": "2027-01-31..."
  }
}`}
                </code>
              </pre>
            </div>
          </div>
        </div>
      </section>
      
      {/* Recent Agents */}
      {recentAgents.length > 0 && (
        <section className="py-24">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between mb-8">
              <h2 className="text-2xl font-bold text-white">Recently Verified</h2>
              <Link to="/agents" className="text-indigo-400 hover:text-indigo-300 flex items-center gap-1">
                View all <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
            
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {recentAgents.map((agent) => (
                <Link
                  key={agent.id}
                  to={`/a/${encodeURIComponent(agent.name)}`}
                  className="card p-4 hover:border-gray-700 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-lg flex items-center justify-center">
                      <Bot className="w-5 h-5 text-white" />
                    </div>
                    <div>
                      <div className="font-medium text-white">{agent.name}</div>
                      <div className="text-sm text-gray-500">
                        Verified {new Date(agent.verified_at).toLocaleDateString()}
                      </div>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        </section>
      )}
      
      {/* For Platforms CTA */}
      <section className="py-24 bg-gradient-to-b from-transparent via-indigo-900/10 to-transparent">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="card p-8 sm:p-12 text-center bg-gradient-to-br from-gray-900 to-gray-900/50 border-indigo-500/20">
            <Building2 className="w-12 h-12 text-indigo-400 mx-auto mb-4" />
            <h2 className="text-2xl sm:text-3xl font-bold text-white mb-4">
              For Platforms
            </h2>
            <p className="text-gray-400 max-w-xl mx-auto mb-6">
              Integrate KnowYourClaw to eliminate spam agents on your platform.
              Simple API, completely free.
            </p>
            <Link to="/platforms" className="btn-primary inline-flex items-center gap-2">
              Learn More <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>
    </div>
  )
}
