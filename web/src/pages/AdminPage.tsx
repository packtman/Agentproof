import { useState, useEffect, useCallback } from 'react'
import { 
  Shield, Building2, Bot, Activity, RefreshCw, 
  Lock, Eye, EyeOff, Ban, CheckCircle2,
  LogOut, AlertTriangle
} from 'lucide-react'

interface Stats {
  platforms: { total: number; active: number }
  agents: { total: number; verified: number; claimed: number }
  challenges: { total: number; completed: number; failed: number; success_rate: number }
  proofs: { active: number }
  verifications: { total: number }
}

interface Platform {
  id: string
  name: string
  domain: string | null
  contact_email: string | null
  tier: string
  rate_limit: number
  status: string
  verifications_count: number
  verifications_this_month: number
  created_at: string
}

interface Agent {
  id: string
  name: string
  description: string | null
  status: string
  verified_at: string | null
  created_at: string
  owner_handle?: string
  owner_provider?: string
}

export default function AdminPage() {
  const [secret, setSecret] = useState('')
  const [sessionToken, setSessionToken] = useState<string | null>(null)
  const [showSecret, setShowSecret] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [loginLoading, setLoginLoading] = useState(false)
  const [retryAfter, setRetryAfter] = useState<number | null>(null)
  
  const [stats, setStats] = useState<Stats | null>(null)
  const [platforms, setPlatforms] = useState<Platform[]>([])
  const [agents, setAgents] = useState<Agent[]>([])
  const [activeTab, setActiveTab] = useState<'overview' | 'platforms' | 'agents'>('overview')
  
  // Check for existing session on mount
  useEffect(() => {
    const stored = sessionStorage.getItem('adminSessionToken')
    if (stored) {
      setSessionToken(stored)
    }
  }, [])
  
  const fetchWithAuth = useCallback(async (url: string, options: RequestInit = {}) => {
    if (!sessionToken) throw new Error('No session')
    
    return fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${sessionToken}`,
        'Content-Type': 'application/json',
      },
    })
  }, [sessionToken])
  
  const fetchData = useCallback(async () => {
    if (!sessionToken) return
    
    setLoading(true)
    try {
      const [statsRes, platformsRes, agentsRes] = await Promise.all([
        fetchWithAuth('/api/v1/admin/stats'),
        fetchWithAuth('/api/v1/admin/platforms'),
        fetchWithAuth('/api/v1/admin/agents')
      ])
      
      if (statsRes.status === 401) {
        // Session expired
        handleLogout()
        setError('Session expired. Please login again.')
        return
      }
      
      const statsData = await statsRes.json()
      const platformsData = await platformsRes.json()
      const agentsData = await agentsRes.json()
      
      setStats(statsData.stats)
      setPlatforms(platformsData.platforms || [])
      setAgents(agentsData.agents || [])
      setError('')
    } catch (err) {
      console.error('Fetch error:', err)
      setError('Failed to load data')
    } finally {
      setLoading(false)
    }
  }, [sessionToken, fetchWithAuth])
  
  // Fetch data when session is available
  useEffect(() => {
    if (sessionToken) {
      fetchData()
    }
  }, [sessionToken, fetchData])
  
  // Countdown for rate limit
  useEffect(() => {
    if (retryAfter && retryAfter > 0) {
      const timer = setInterval(() => {
        setRetryAfter(prev => prev && prev > 1 ? prev - 1 : null)
      }, 1000)
      return () => clearInterval(timer)
    }
  }, [retryAfter])
  
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoginLoading(true)
    setError('')
    
    try {
      const res = await fetch('/api/v1/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret })
      })
      
      const data = await res.json()
      
      if (res.status === 429) {
        setRetryAfter(data.retry_after_seconds || 60)
        setError('Too many attempts. Please wait.')
        return
      }
      
      if (!data.success) {
        setError(data.error || 'Login failed')
        return
      }
      
      // Store session
      setSessionToken(data.session_token)
      sessionStorage.setItem('adminSessionToken', data.session_token)
      setSecret('')
    } catch (err) {
      setError('Connection error')
    } finally {
      setLoginLoading(false)
    }
  }
  
  const handleLogout = async () => {
    if (sessionToken) {
      try {
        await fetchWithAuth('/api/v1/admin/logout', { method: 'POST' })
      } catch (e) {
        // Ignore errors on logout
      }
    }
    setSessionToken(null)
    sessionStorage.removeItem('adminSessionToken')
    setStats(null)
    setPlatforms([])
    setAgents([])
  }
  
  const updatePlatformStatus = async (platformId: string, status: string) => {
    try {
      await fetchWithAuth(`/api/v1/admin/platforms/${platformId}`, {
        method: 'PATCH',
        body: JSON.stringify({ status })
      })
      fetchData()
    } catch (err) {
      console.error('Failed to update platform:', err)
    }
  }
  
  const updateAgentStatus = async (agentId: string, status: string) => {
    try {
      await fetchWithAuth(`/api/v1/admin/agents/${agentId}`, {
        method: 'PATCH',
        body: JSON.stringify({ status })
      })
      fetchData()
    } catch (err) {
      console.error('Failed to update agent:', err)
    }
  }
  
  // Login screen
  if (!sessionToken) {
    return (
      <div className="min-h-[60vh] flex items-center justify-center">
        <div className="card p-8 max-w-md w-full">
          <div className="text-center mb-6">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-indigo-500/20 rounded-2xl mb-4">
              <Lock className="w-8 h-8 text-indigo-400" />
            </div>
            <h1 className="text-2xl font-bold text-white">Admin Access</h1>
            <p className="text-gray-400 mt-2">Enter your admin credentials</p>
          </div>
          
          <form onSubmit={handleLogin} className="space-y-4">
            <div className="relative">
              <input
                type={showSecret ? 'text' : 'password'}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder="Admin Secret"
                className="input w-full pr-10"
                required
                disabled={!!retryAfter}
                autoComplete="off"
              />
              <button
                type="button"
                onClick={() => setShowSecret(!showSecret)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
              >
                {showSecret ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
            
            {error && (
              <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <p className="text-red-400 text-sm">{error}</p>
              </div>
            )}
            
            {retryAfter && (
              <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                <p className="text-yellow-400 text-sm">
                  Rate limited. Try again in {retryAfter}s
                </p>
              </div>
            )}
            
            <button
              type="submit"
              disabled={loginLoading || !!retryAfter}
              className="btn-primary w-full"
            >
              {loginLoading ? 'Authenticating...' : 'Login'}
            </button>
          </form>
          
          <div className="mt-6 p-3 bg-gray-800/50 rounded-lg">
            <p className="text-xs text-gray-500 text-center">
              <Shield className="w-3 h-3 inline mr-1" />
              Session expires after 24 hours. 5 failed attempts = 15 min lockout.
            </p>
          </div>
        </div>
      </div>
    )
  }
  
  // Dashboard
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white">Admin Dashboard</h1>
          <p className="text-gray-400 mt-1">Manage platforms, agents, and view stats</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={fetchData}
            disabled={loading}
            className="btn-secondary flex items-center gap-2"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleLogout}
            className="btn-secondary flex items-center gap-2 text-red-400 hover:text-red-300"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        </div>
      </div>
      
      {/* Tabs */}
      <div className="flex gap-2 mb-8 border-b border-gray-800 pb-4">
        {(['overview', 'platforms', 'agents'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              activeTab === tab
                ? 'bg-indigo-500 text-white'
                : 'text-gray-400 hover:text-white hover:bg-gray-800'
            }`}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>
      
      {/* Overview Tab */}
      {activeTab === 'overview' && stats && (
        <div className="space-y-8">
          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="card p-6">
              <div className="flex items-center gap-3 mb-2">
                <Building2 className="w-5 h-5 text-indigo-400" />
                <span className="text-gray-400 text-sm">Platforms</span>
              </div>
              <div className="text-3xl font-bold text-white">{stats.platforms.total}</div>
              <div className="text-sm text-gray-500">{stats.platforms.active} active</div>
            </div>
            
            <div className="card p-6">
              <div className="flex items-center gap-3 mb-2">
                <Bot className="w-5 h-5 text-green-400" />
                <span className="text-gray-400 text-sm">Agents</span>
              </div>
              <div className="text-3xl font-bold text-white">{stats.agents.total}</div>
              <div className="text-sm text-gray-500">{stats.agents.claimed} claimed</div>
            </div>
            
            <div className="card p-6">
              <div className="flex items-center gap-3 mb-2">
                <Activity className="w-5 h-5 text-yellow-400" />
                <span className="text-gray-400 text-sm">Challenges</span>
              </div>
              <div className="text-3xl font-bold text-white">{stats.challenges.total}</div>
              <div className="text-sm text-gray-500">{stats.challenges.success_rate}% success</div>
            </div>
            
            <div className="card p-6">
              <div className="flex items-center gap-3 mb-2">
                <Shield className="w-5 h-5 text-blue-400" />
                <span className="text-gray-400 text-sm">Verifications</span>
              </div>
              <div className="text-3xl font-bold text-white">{stats.verifications.total}</div>
              <div className="text-sm text-gray-500">{stats.proofs.active} active proofs</div>
            </div>
          </div>
          
          {/* Recent Activity */}
          <div className="grid md:grid-cols-2 gap-8">
            <div className="card p-6">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Building2 className="w-5 h-5 text-indigo-400" />
                Recent Platforms
              </h3>
              <div className="space-y-3">
                {platforms.slice(0, 5).map((p) => (
                  <div key={p.id} className="flex items-center justify-between p-3 bg-gray-900/50 rounded-lg">
                    <div>
                      <div className="font-medium text-white">{p.name}</div>
                      <div className="text-sm text-gray-500">{p.domain || 'No domain'}</div>
                    </div>
                    <div className="text-right">
                      <div className={`text-sm ${p.status === 'active' ? 'text-green-400' : 'text-red-400'}`}>
                        {p.status}
                      </div>
                      <div className="text-xs text-gray-500">
                        {new Date(p.created_at).toLocaleDateString()}
                      </div>
                    </div>
                  </div>
                ))}
                {platforms.length === 0 && (
                  <p className="text-gray-500 text-center py-4">No platforms yet</p>
                )}
              </div>
            </div>
            
            <div className="card p-6">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Bot className="w-5 h-5 text-green-400" />
                Recent Agents
              </h3>
              <div className="space-y-3">
                {agents.slice(0, 5).map((a) => (
                  <div key={a.id} className="flex items-center justify-between p-3 bg-gray-900/50 rounded-lg">
                    <div>
                      <div className="font-medium text-white">{a.name}</div>
                      <div className="text-sm text-gray-500">
                        {a.owner_handle ? `@${a.owner_handle}` : 'Unclaimed'}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`text-sm ${a.status === 'verified' ? 'text-green-400' : 'text-yellow-400'}`}>
                        {a.status}
                      </div>
                      <div className="text-xs text-gray-500">
                        {new Date(a.created_at).toLocaleDateString()}
                      </div>
                    </div>
                  </div>
                ))}
                {agents.length === 0 && (
                  <p className="text-gray-500 text-center py-4">No agents yet</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
      
      {/* Platforms Tab */}
      {activeTab === 'platforms' && (
        <div className="card overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-900/50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Platform</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Domain</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Tier</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Verifications</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {platforms.map((p) => (
                <tr key={p.id} className="hover:bg-gray-900/30">
                  <td className="px-6 py-4">
                    <div className="font-medium text-white">{p.name}</div>
                    <div className="text-xs text-gray-500 font-mono">{p.id}</div>
                  </td>
                  <td className="px-6 py-4 text-gray-300">{p.domain || '-'}</td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      p.tier === 'enterprise' ? 'bg-purple-500/20 text-purple-400' :
                      p.tier === 'platform' ? 'bg-blue-500/20 text-blue-400' :
                      'bg-gray-500/20 text-gray-400'
                    }`}>
                      {p.tier}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-gray-300">
                    <div>{p.verifications_count} total</div>
                    <div className="text-xs text-gray-500">{p.verifications_this_month} this month</div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      p.status === 'active' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                    }`}>
                      {p.status}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex gap-2">
                      {p.status === 'active' ? (
                        <button
                          onClick={() => updatePlatformStatus(p.id, 'suspended')}
                          className="p-2 text-red-400 hover:bg-red-500/20 rounded-lg"
                          title="Suspend"
                        >
                          <Ban className="w-4 h-4" />
                        </button>
                      ) : (
                        <button
                          onClick={() => updatePlatformStatus(p.id, 'active')}
                          className="p-2 text-green-400 hover:bg-green-500/20 rounded-lg"
                          title="Activate"
                        >
                          <CheckCircle2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          
          {platforms.length === 0 && (
            <div className="text-center py-12 text-gray-500">
              No platforms registered yet
            </div>
          )}
        </div>
      )}
      
      {/* Agents Tab */}
      {activeTab === 'agents' && (
        <div className="card overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-900/50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Agent</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Owner</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Verified</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {agents.map((a) => (
                <tr key={a.id} className="hover:bg-gray-900/30">
                  <td className="px-6 py-4">
                    <div className="font-medium text-white">{a.name}</div>
                    <div className="text-xs text-gray-500 font-mono">{a.id}</div>
                  </td>
                  <td className="px-6 py-4 text-gray-300">
                    {a.owner_handle ? (
                      <div className="flex items-center gap-2">
                        <span>@{a.owner_handle}</span>
                        <span className="text-xs text-gray-500">({a.owner_provider})</span>
                      </div>
                    ) : (
                      <span className="text-gray-500">Unclaimed</span>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      a.status === 'verified' ? 'bg-green-500/20 text-green-400' :
                      a.status === 'suspended' ? 'bg-red-500/20 text-red-400' :
                      'bg-yellow-500/20 text-yellow-400'
                    }`}>
                      {a.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-gray-300 text-sm">
                    {a.verified_at ? new Date(a.verified_at).toLocaleString() : '-'}
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex gap-2">
                      {a.status === 'verified' ? (
                        <button
                          onClick={() => updateAgentStatus(a.id, 'suspended')}
                          className="p-2 text-red-400 hover:bg-red-500/20 rounded-lg"
                          title="Suspend"
                        >
                          <Ban className="w-4 h-4" />
                        </button>
                      ) : a.status === 'suspended' ? (
                        <button
                          onClick={() => updateAgentStatus(a.id, 'verified')}
                          className="p-2 text-green-400 hover:bg-green-500/20 rounded-lg"
                          title="Reinstate"
                        >
                          <CheckCircle2 className="w-4 h-4" />
                        </button>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          
          {agents.length === 0 && (
            <div className="text-center py-12 text-gray-500">
              No agents registered yet
            </div>
          )}
        </div>
      )}
    </div>
  )
}
