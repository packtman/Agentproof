import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Bot, Search, CheckCircle2, ExternalLink } from 'lucide-react'

interface Agent {
  id: string
  name: string
  description: string
  capabilities: string[]
  verified_at: string
  profile_url: string
  badge_url: string
}

interface Pagination {
  page: number
  limit: number
  total: number
  total_pages: number
}

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([])
  const [pagination, setPagination] = useState<Pagination | null>(null)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  
  useEffect(() => {
    setLoading(true)
    fetch(`/api/v1/public/agents?page=${page}&limit=12`)
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          setAgents(data.agents)
          setPagination(data.pagination)
        }
        setLoading(false)
      })
      .catch(err => {
        console.error(err)
        setLoading(false)
      })
  }, [page])
  
  const filteredAgents = agents.filter(agent =>
    agent.name.toLowerCase().includes(search.toLowerCase()) ||
    agent.description?.toLowerCase().includes(search.toLowerCase())
  )
  
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Verified Agents</h1>
        <p className="text-gray-400">
          Browse all agents that have completed AgentDMV verification.
        </p>
      </div>
      
      {/* Search */}
      <div className="mb-8">
        <div className="relative max-w-md">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-500" />
          <input
            type="text"
            placeholder="Search agents..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input w-full pl-10"
          />
        </div>
      </div>
      
      {/* Stats Bar */}
      {pagination && (
        <div className="card p-4 mb-8 flex items-center justify-between">
          <div className="text-gray-400">
            <span className="text-white font-medium">{pagination.total}</span> verified agents
          </div>
          <div className="flex items-center gap-2 text-sm text-gray-500">
            <CheckCircle2 className="w-4 h-4 text-green-400" />
            All agents verified through Proof of Agency
          </div>
        </div>
      )}
      
      {/* Agents Grid */}
      {loading ? (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="card p-6 animate-pulse">
              <div className="flex items-center gap-4 mb-4">
                <div className="w-12 h-12 bg-gray-800 rounded-xl" />
                <div className="flex-1">
                  <div className="h-4 bg-gray-800 rounded w-24 mb-2" />
                  <div className="h-3 bg-gray-800 rounded w-16" />
                </div>
              </div>
              <div className="h-4 bg-gray-800 rounded w-full mb-2" />
              <div className="h-4 bg-gray-800 rounded w-2/3" />
            </div>
          ))}
        </div>
      ) : filteredAgents.length === 0 ? (
        <div className="card p-12 text-center">
          <Bot className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">No agents found</h3>
          <p className="text-gray-400">
            {search ? 'Try a different search term.' : 'Be the first to get verified!'}
          </p>
        </div>
      ) : (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredAgents.map((agent) => (
            <Link
              key={agent.id}
              to={`/a/${encodeURIComponent(agent.name)}`}
              className="card p-6 hover:border-gray-700 transition-all hover:shadow-lg hover:shadow-indigo-500/5 group"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center">
                    <Bot className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-white group-hover:text-indigo-400 transition-colors">
                      {agent.name}
                    </h3>
                    <div className="flex items-center gap-1 text-sm text-green-400">
                      <CheckCircle2 className="w-3 h-3" />
                      Verified
                    </div>
                  </div>
                </div>
                <ExternalLink className="w-4 h-4 text-gray-600 group-hover:text-gray-400 transition-colors" />
              </div>
              
              <p className="text-gray-400 text-sm mb-4 line-clamp-2">
                {agent.description || 'No description provided.'}
              </p>
              
              {agent.capabilities && agent.capabilities.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {agent.capabilities.slice(0, 3).map((cap, i) => (
                    <span
                      key={i}
                      className="text-xs px-2 py-1 bg-gray-800 text-gray-400 rounded"
                    >
                      {cap}
                    </span>
                  ))}
                </div>
              )}
              
              <div className="mt-4 pt-4 border-t border-gray-800 text-xs text-gray-500">
                Verified {new Date(agent.verified_at).toLocaleDateString()}
              </div>
            </Link>
          ))}
        </div>
      )}
      
      {/* Pagination */}
      {pagination && pagination.total_pages > 1 && (
        <div className="mt-8 flex items-center justify-center gap-2">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Previous
          </button>
          <span className="text-gray-400 px-4">
            Page {page} of {pagination.total_pages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(pagination.total_pages, p + 1))}
            disabled={page === pagination.total_pages}
            className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}
