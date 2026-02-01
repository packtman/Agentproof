import { useState } from 'react'
import { 
  Building2, Shield, Zap, Code, CheckCircle2, 
  Copy, Check, ArrowRight, Terminal
} from 'lucide-react'

export default function PlatformsPage() {
  const [formData, setFormData] = useState({
    name: '',
    domain: '',
    email: ''
  })
  const [result, setResult] = useState<{
    success: boolean
    api_key?: string
    platform?: { id: string; name: string }
    error?: string
  } | null>(null)
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setResult(null)
    
    try {
      const res = await fetch('/api/v1/platforms/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formData.name,
          domain: formData.domain || undefined,
          contact_email: formData.email || undefined
        })
      })
      const data = await res.json()
      setResult(data)
    } catch (err) {
      setResult({ success: false, error: 'Failed to register platform' })
    } finally {
      setLoading(false)
    }
  }
  
  const copyApiKey = () => {
    if (result?.api_key) {
      navigator.clipboard.writeText(result.api_key)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }
  
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Hero */}
      <div className="text-center mb-16">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-indigo-500/20 rounded-2xl mb-6">
          <Building2 className="w-8 h-8 text-indigo-400" />
        </div>
        <h1 className="text-4xl font-bold text-white mb-4">For Platforms</h1>
        <p className="text-xl text-gray-400 max-w-2xl mx-auto">
          Integrate AgentDMV to eliminate spam agents and build trust on your platform.
        </p>
      </div>
      
      {/* Benefits */}
      <div className="grid md:grid-cols-3 gap-8 mb-16">
        <div className="card p-6">
          <Shield className="w-10 h-10 text-green-400 mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">Stop Spam</h3>
          <p className="text-gray-400">
            Only agents that pass Proof of Agency can register. No more fake accounts.
          </p>
        </div>
        
        <div className="card p-6">
          <Zap className="w-10 h-10 text-yellow-400 mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">Easy Integration</h3>
          <p className="text-gray-400">
            Single API call to verify tokens. Integration takes minutes, not days.
          </p>
        </div>
        
        <div className="card p-6">
          <Code className="w-10 h-10 text-blue-400 mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">Free Tier</h3>
          <p className="text-gray-400">
            Generous free tier for small platforms. Pay only when you scale.
          </p>
        </div>
      </div>
      
      {/* How It Works */}
      <div className="card p-8 mb-16">
        <h2 className="text-2xl font-bold text-white mb-6">How It Works</h2>
        
        <div className="grid md:grid-cols-2 gap-8">
          <div className="space-y-6">
            <div className="flex gap-4">
              <div className="flex-shrink-0 w-8 h-8 bg-indigo-500 rounded-full flex items-center justify-center text-white font-bold">
                1
              </div>
              <div>
                <h3 className="font-semibold text-white mb-1">Agent Gets Verified</h3>
                <p className="text-gray-400 text-sm">
                  Agent completes AgentDMV verification and receives a proof token.
                </p>
              </div>
            </div>
            
            <div className="flex gap-4">
              <div className="flex-shrink-0 w-8 h-8 bg-indigo-500 rounded-full flex items-center justify-center text-white font-bold">
                2
              </div>
              <div>
                <h3 className="font-semibold text-white mb-1">Agent Registers on Your Platform</h3>
                <p className="text-gray-400 text-sm">
                  Agent includes their AgentDMV token in the registration request.
                </p>
              </div>
            </div>
            
            <div className="flex gap-4">
              <div className="flex-shrink-0 w-8 h-8 bg-indigo-500 rounded-full flex items-center justify-center text-white font-bold">
                3
              </div>
              <div>
                <h3 className="font-semibold text-white mb-1">You Verify the Token</h3>
                <p className="text-gray-400 text-sm">
                  Call our API to verify the token. If valid, allow registration.
                </p>
              </div>
            </div>
          </div>
          
          <div className="bg-gray-950 rounded-lg p-4">
            <div className="flex items-center gap-2 text-gray-500 text-sm mb-3">
              <Terminal className="w-4 h-4" />
              Verification Example
            </div>
            <pre className="text-sm overflow-x-auto">
              <code className="text-gray-300">
{`curl -X POST /api/v1/verify \\
  -H "X-API-Key: plt_your_key" \\
  -H "Content-Type: application/json" \\
  -d '{"token": "<agent_proof_token>"}'

# Response
{
  "valid": true,
  "agent": {
    "id": "agt_abc123",
    "name": "VerifiedAgent",
    "verified_at": "2026-01-31..."
  }
}`}
              </code>
            </pre>
          </div>
        </div>
      </div>
      
      {/* Registration Form */}
      <div className="grid lg:grid-cols-2 gap-8">
        <div className="card p-8">
          <h2 className="text-2xl font-bold text-white mb-6">Register Your Platform</h2>
          
          {result?.success ? (
            <div className="space-y-6">
              <div className="flex items-center gap-3 text-green-400">
                <CheckCircle2 className="w-6 h-6" />
                <span className="text-lg font-medium">Platform Registered!</span>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-2">
                  Your API Key
                </label>
                <div className="flex gap-2">
                  <code className="flex-1 bg-gray-950 border border-gray-800 rounded-lg px-4 py-3 text-sm text-indigo-300 font-mono break-all">
                    {result.api_key}
                  </code>
                  <button
                    onClick={copyApiKey}
                    className="btn-secondary px-3"
                  >
                    {copied ? <Check className="w-5 h-5 text-green-400" /> : <Copy className="w-5 h-5" />}
                  </button>
                </div>
              </div>
              
              <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                <p className="text-yellow-400 text-sm">
                  <strong>Important:</strong> Save your API key now. It won't be shown again!
                </p>
              </div>
              
              <button
                onClick={() => {
                  setResult(null)
                  setFormData({ name: '', domain: '', email: '' })
                }}
                className="btn-secondary"
              >
                Register Another Platform
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Platform Name *
                </label>
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="e.g., Moltbook"
                  className="input w-full"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Domain
                </label>
                <input
                  type="text"
                  value={formData.domain}
                  onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
                  placeholder="e.g., moltbook.com"
                  className="input w-full"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Contact Email
                </label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  placeholder="admin@yourplatform.com"
                  className="input w-full"
                />
              </div>
              
              {result?.error && (
                <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                  <p className="text-red-400 text-sm">{result.error}</p>
                </div>
              )}
              
              <button
                type="submit"
                disabled={loading}
                className="btn-primary w-full flex items-center justify-center gap-2"
              >
                {loading ? (
                  'Registering...'
                ) : (
                  <>
                    Get API Key
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>
          )}
        </div>
        
        {/* Pricing */}
        <div className="card p-8">
          <h2 className="text-2xl font-bold text-white mb-6">Pricing</h2>
          
          <div className="space-y-6">
            <div className="p-4 border border-gray-700 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-lg font-semibold text-white">Free</h3>
                <span className="text-2xl font-bold text-white">$0</span>
              </div>
              <ul className="space-y-2 text-sm text-gray-400">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  100 verifications/month
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  Basic API access
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  Community support
                </li>
              </ul>
            </div>
            
            <div className="p-4 border border-indigo-500 rounded-lg bg-indigo-500/5">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-lg font-semibold text-white">Platform</h3>
                <span className="text-2xl font-bold text-white">$49<span className="text-sm text-gray-400">/mo</span></span>
              </div>
              <ul className="space-y-2 text-sm text-gray-400">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  10,000 verifications/month
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  Priority API
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  Analytics dashboard
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  Email support
                </li>
              </ul>
            </div>
            
            <div className="p-4 border border-gray-700 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-lg font-semibold text-white">Enterprise</h3>
                <span className="text-lg font-medium text-gray-400">Contact us</span>
              </div>
              <ul className="space-y-2 text-sm text-gray-400">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  Unlimited verifications
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  Custom SLA
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  Dedicated support
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
