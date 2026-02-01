import { useState, useEffect } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { CheckCircle2, XCircle, Copy, Check, Loader2, ArrowRight } from 'lucide-react'

export default function PlatformVerifyPage() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading')
  const [result, setResult] = useState<{
    platform?: { id: string; name: string; tier: string }
    api_key?: string
    error?: string
    usage?: { verification_endpoint: string; header: string; example: string }
  } | null>(null)
  const [copied, setCopied] = useState(false)
  
  useEffect(() => {
    if (!token) {
      setStatus('error')
      setResult({ error: 'No verification token provided' })
      return
    }
    
    const verifyEmail = async () => {
      try {
        const res = await fetch(`/api/v1/platforms/verify?token=${encodeURIComponent(token)}`)
        const data = await res.json()
        
        if (data.success) {
          setStatus('success')
          setResult(data)
        } else {
          setStatus('error')
          setResult({ error: data.error || 'Verification failed' })
        }
      } catch {
        setStatus('error')
        setResult({ error: 'Failed to verify email. Please try again.' })
      }
    }
    
    verifyEmail()
  }, [token])
  
  const copyApiKey = () => {
    if (result?.api_key) {
      navigator.clipboard.writeText(result.api_key)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }
  
  if (status === 'loading') {
    return (
      <div className="min-h-[60vh] flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="w-12 h-12 text-indigo-400 animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Verifying your email...</p>
        </div>
      </div>
    )
  }
  
  if (status === 'error') {
    return (
      <div className="min-h-[60vh] flex items-center justify-center">
        <div className="card p-8 max-w-md w-full text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-red-500/20 rounded-full mb-6">
            <XCircle className="w-8 h-8 text-red-400" />
          </div>
          <h1 className="text-2xl font-bold text-white mb-4">Verification Failed</h1>
          <p className="text-gray-400 mb-6">{result?.error}</p>
          <Link to="/platforms" className="btn-primary inline-flex items-center gap-2">
            Try Again
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </div>
    )
  }
  
  return (
    <div className="max-w-2xl mx-auto px-4 py-12">
      <div className="card p-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-green-500/20 rounded-full mb-4">
            <CheckCircle2 className="w-8 h-8 text-green-400" />
          </div>
          <h1 className="text-2xl font-bold text-white mb-2">Email Verified!</h1>
          <p className="text-gray-400">
            Your platform <strong className="text-white">{result?.platform?.name}</strong> is now active.
          </p>
        </div>
        
        {/* API Key */}
        <div className="mb-8">
          <label className="block text-sm font-medium text-gray-400 mb-2">
            Your API Key
          </label>
          <div className="flex gap-2">
            <code className="flex-1 bg-gray-950 border border-gray-800 rounded-lg px-4 py-3 text-sm text-indigo-300 font-mono break-all">
              {result?.api_key}
            </code>
            <button
              onClick={copyApiKey}
              className="btn-secondary px-3 flex-shrink-0"
            >
              {copied ? <Check className="w-5 h-5 text-green-400" /> : <Copy className="w-5 h-5" />}
            </button>
          </div>
        </div>
        
        {/* Warning */}
        <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg mb-8">
          <p className="text-yellow-400 text-sm">
            <strong>⚠️ Important:</strong> Save your API key now! It won't be shown again.
            <br />
            <span className="text-yellow-400/70">We've also sent it to your email as a backup.</span>
          </p>
        </div>
        
        {/* Quick Start */}
        <div className="bg-gray-900/50 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Quick Start</h3>
          
          <p className="text-gray-400 text-sm mb-3">Verify an agent token:</p>
          
          <pre className="bg-gray-950 rounded-lg p-4 text-sm overflow-x-auto mb-4">
            <code className="text-gray-300">
{`curl -X POST ${result?.usage?.verification_endpoint || '/api/v1/verify'} \\
  -H "X-API-Key: ${result?.api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{"token": "<agent_proof_token>"}'`}
            </code>
          </pre>
          
          <Link to="/docs" className="text-indigo-400 hover:text-indigo-300 text-sm">
            View full documentation →
          </Link>
        </div>
        
        {/* Platform Info */}
        <div className="mt-8 pt-6 border-t border-gray-800 text-center text-sm text-gray-500">
          Platform ID: <code className="text-gray-400">{result?.platform?.id}</code>
          <span className="mx-2">•</span>
          Tier: <span className="text-gray-400">{result?.platform?.tier}</span>
        </div>
      </div>
    </div>
  )
}
