import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { 
  Bot, CheckCircle2, Calendar, Copy,
  ArrowLeft, Shield, Code
} from 'lucide-react'

interface Agent {
  id: string
  name: string
  description: string
  status: string
  verified_at: string
  capabilities: string[]
  model_family?: string
  framework?: string
  owner?: {
    claimed: boolean
    handle?: string
    provider?: string
  }
  badge_url: string
  profile_url: string
}

export default function AgentProfilePage() {
  const { name } = useParams<{ name: string }>()
  const [agent, setAgent] = useState<Agent | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  
  useEffect(() => {
    // We need to find the agent by name, but our API uses ID
    // For now, fetch all agents and find by name
    // In production, add a /agents/by-name/:name endpoint
    fetch('/api/v1/public/agents?limit=100')
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          const found = data.agents.find((a: Agent) => a.name === name)
          if (found) {
            setAgent(found)
          } else {
            setError('Agent not found')
          }
        }
        setLoading(false)
      })
      .catch(err => {
        console.error(err)
        setError('Failed to load agent')
        setLoading(false)
      })
  }, [name])
  
  const copyBadgeCode = () => {
    if (!agent) return
    const badgeCode = `[![KnowYourClaw Verified](${window.location.origin}/badge/${agent.id}.svg)](${window.location.origin}/a/${encodeURIComponent(agent.name)})`
    navigator.clipboard.writeText(badgeCode)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  
  if (loading) {
    return (
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-800 rounded w-48 mb-8" />
          <div className="card p-8">
            <div className="flex items-center gap-6 mb-6">
              <div className="w-20 h-20 bg-gray-800 rounded-2xl" />
              <div>
                <div className="h-6 bg-gray-800 rounded w-32 mb-2" />
                <div className="h-4 bg-gray-800 rounded w-24" />
              </div>
            </div>
            <div className="h-4 bg-gray-800 rounded w-full mb-2" />
            <div className="h-4 bg-gray-800 rounded w-2/3" />
          </div>
        </div>
      </div>
    )
  }
  
  if (error || !agent) {
    return (
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <Link to="/agents" className="inline-flex items-center gap-2 text-gray-400 hover:text-white mb-8">
          <ArrowLeft className="w-4 h-4" />
          Back to Agents
        </Link>
        
        <div className="card p-12 text-center">
          <Bot className="w-16 h-16 text-gray-600 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Agent Not Found</h2>
          <p className="text-gray-400">
            The agent "{name}" doesn't exist or hasn't been verified yet.
          </p>
        </div>
      </div>
    )
  }
  
  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Back Link */}
      <Link to="/agents" className="inline-flex items-center gap-2 text-gray-400 hover:text-white mb-8 transition-colors">
        <ArrowLeft className="w-4 h-4" />
        Back to Agents
      </Link>
      
      {/* Main Card */}
      <div className="card overflow-hidden">
        {/* Header with gradient */}
        <div className="h-32 bg-gradient-to-br from-indigo-600 via-purple-600 to-pink-600" />
        
        {/* Profile Info */}
        <div className="px-8 pb-8">
          <div className="flex flex-col sm:flex-row sm:items-end gap-6 -mt-12">
            <div className="w-24 h-24 bg-gray-900 rounded-2xl border-4 border-gray-900 flex items-center justify-center">
              <Bot className="w-12 h-12 text-indigo-400" />
            </div>
            
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-1">
                <h1 className="text-2xl font-bold text-white">{agent.name}</h1>
                <span className="inline-flex items-center gap-1 bg-green-500/20 text-green-400 text-sm px-2 py-0.5 rounded-full">
                  <CheckCircle2 className="w-3 h-3" />
                  Verified
                </span>
              </div>
              <p className="text-gray-400">{agent.id}</p>
            </div>
          </div>
          
          {/* Description */}
          <div className="mt-8">
            <h2 className="text-sm font-medium text-gray-500 uppercase tracking-wider mb-2">
              About
            </h2>
            <p className="text-gray-300">
              {agent.description || 'No description provided.'}
            </p>
          </div>
          
          {/* Details Grid */}
          <div className="mt-8 grid sm:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <h3 className="text-sm font-medium text-gray-500 mb-1">Verified</h3>
                <div className="flex items-center gap-2 text-white">
                  <Calendar className="w-4 h-4 text-gray-500" />
                  {new Date(agent.verified_at).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                  })}
                </div>
              </div>
              
              {agent.model_family && (
                <div>
                  <h3 className="text-sm font-medium text-gray-500 mb-1">Model Family</h3>
                  <p className="text-white">{agent.model_family}</p>
                </div>
              )}
              
              {agent.framework && (
                <div>
                  <h3 className="text-sm font-medium text-gray-500 mb-1">Framework</h3>
                  <p className="text-white">{agent.framework}</p>
                </div>
              )}
            </div>
            
            <div>
              <h3 className="text-sm font-medium text-gray-500 mb-2">Capabilities</h3>
              {agent.capabilities && agent.capabilities.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {agent.capabilities.map((cap, i) => (
                    <span
                      key={i}
                      className="px-3 py-1 bg-gray-800 text-gray-300 rounded-full text-sm"
                    >
                      {cap}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-gray-500">No capabilities listed</p>
              )}
            </div>
          </div>
          
          {/* Owner Status */}
          <div className="mt-8 p-4 bg-gray-800/50 rounded-lg">
            <div className="flex items-center gap-3">
              <Shield className={`w-5 h-5 ${agent.owner?.claimed ? 'text-green-400' : 'text-gray-500'}`} />
              <div>
                <p className="text-white font-medium">
                  {agent.owner?.claimed ? 'Claimed by Owner' : 'Unclaimed'}
                </p>
                <p className="text-sm text-gray-400">
                  {agent.owner?.claimed && agent.owner?.handle
                    ? <>Owned by <a href={`https://x.com/${agent.owner.handle}`} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300">@{agent.owner.handle}</a></>
                    : 'The owner has not yet claimed this agent.'
                  }
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      {/* Badge Embed Section */}
      <div className="card p-6 mt-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Code className="w-5 h-5 text-gray-500" />
          Embed Badge
        </h2>
        
        <div className="bg-gray-950 rounded-lg p-4 mb-4">
          <code className="text-sm text-gray-300 break-all">
            {`[![KnowYourClaw Verified](${window.location.origin}/badge/${agent.id}.svg)](${window.location.origin}/a/${encodeURIComponent(agent.name)})`}
          </code>
        </div>
        
        <button
          onClick={copyBadgeCode}
          className="btn-secondary inline-flex items-center gap-2"
        >
          <Copy className="w-4 h-4" />
          {copied ? 'Copied!' : 'Copy Markdown'}
        </button>
      </div>
      
      {/* Verification Details */}
      <div className="card p-6 mt-6">
        <h2 className="text-lg font-semibold text-white mb-4">Verification Details</h2>
        
        <div className="space-y-3 text-sm">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-4 h-4 text-green-400" />
            <span className="text-gray-300">Cryptographic signature verified</span>
          </div>
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-4 h-4 text-green-400" />
            <span className="text-gray-300">Tool-use challenge completed</span>
          </div>
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-4 h-4 text-green-400" />
            <span className="text-gray-300">Reasoning task passed</span>
          </div>
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-4 h-4 text-green-400" />
            <span className="text-gray-300">Unique content generated</span>
          </div>
        </div>
      </div>
    </div>
  )
}
