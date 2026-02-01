import React, { useState, useEffect } from 'react'
import { FileText, ExternalLink, Copy, Check } from 'lucide-react'

export default function DocsPage() {
  const [markdown, setMarkdown] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [copied, setCopied] = useState<string | null>(null)
  
  useEffect(() => {
    fetch('/verify.md')
      .then(res => res.text())
      .then(text => {
        setMarkdown(text)
        setLoading(false)
      })
      .catch(err => {
        console.error(err)
        setLoading(false)
      })
  }, [])
  
  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopied(id)
    setTimeout(() => setCopied(null), 2000)
  }
  
  // Simple markdown rendering with code blocks
  const renderMarkdown = (md: string) => {
    const lines = md.split('\n')
    const elements: React.ReactElement[] = []
    let inCodeBlock = false
    let codeContent = ''
    let codeBlockId = 0
    
    lines.forEach((line, index) => {
      if (line.startsWith('```')) {
        if (!inCodeBlock) {
          inCodeBlock = true
          codeContent = ''
        } else {
          inCodeBlock = false
          const blockId = `code-${codeBlockId++}`
          elements.push(
            <div key={blockId} className="relative group my-4">
              <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
                <button
                  onClick={() => copyToClipboard(codeContent.trim(), blockId)}
                  className="p-2 bg-gray-700 rounded hover:bg-gray-600 transition-colors"
                >
                  {copied === blockId ? (
                    <Check className="w-4 h-4 text-green-400" />
                  ) : (
                    <Copy className="w-4 h-4 text-gray-400" />
                  )}
                </button>
              </div>
              <pre className="bg-gray-950 border border-gray-800 rounded-lg p-4 overflow-x-auto">
                <code className="text-sm text-gray-300">{codeContent.trim()}</code>
              </pre>
            </div>
          )
        }
        return
      }
      
      if (inCodeBlock) {
        codeContent += line + '\n'
        return
      }
      
      // Headers
      if (line.startsWith('# ')) {
        elements.push(
          <h1 key={index} className="text-3xl font-bold text-white mt-8 mb-4">
            {line.slice(2)}
          </h1>
        )
      } else if (line.startsWith('## ')) {
        elements.push(
          <h2 key={index} className="text-2xl font-bold text-white mt-8 mb-3 pb-2 border-b border-gray-800">
            {line.slice(3)}
          </h2>
        )
      } else if (line.startsWith('### ')) {
        elements.push(
          <h3 key={index} className="text-xl font-semibold text-white mt-6 mb-2">
            {line.slice(4)}
          </h3>
        )
      } else if (line.startsWith('#### ')) {
        elements.push(
          <h4 key={index} className="text-lg font-semibold text-gray-200 mt-4 mb-2">
            {line.slice(5)}
          </h4>
        )
      }
      // Horizontal rule
      else if (line === '---') {
        elements.push(<hr key={index} className="my-8 border-gray-800" />)
      }
      // List items
      else if (line.startsWith('- ')) {
        elements.push(
          <li key={index} className="text-gray-300 ml-4">
            {renderInlineMarkdown(line.slice(2))}
          </li>
        )
      }
      // Table handling (simplified)
      else if (line.startsWith('|')) {
        // Skip for now - tables need more complex handling
      }
      // Paragraphs
      else if (line.trim()) {
        elements.push(
          <p key={index} className="text-gray-300 my-3 leading-relaxed">
            {renderInlineMarkdown(line)}
          </p>
        )
      }
    })
    
    return elements
  }
  
  // Handle inline markdown (bold, code, links)
  const renderInlineMarkdown = (text: string): React.ReactNode => {
    // Replace inline code
    const parts = text.split(/(`[^`]+`)/g)
    return parts.map((part, i) => {
      if (part.startsWith('`') && part.endsWith('`')) {
        return (
          <code key={i} className="bg-gray-800 text-indigo-300 px-1.5 py-0.5 rounded text-sm">
            {part.slice(1, -1)}
          </code>
        )
      }
      // Handle bold
      const boldParts = part.split(/(\*\*[^*]+\*\*)/g)
      return boldParts.map((bp, j) => {
        if (bp.startsWith('**') && bp.endsWith('**')) {
          return <strong key={`${i}-${j}`} className="text-white font-semibold">{bp.slice(2, -2)}</strong>
        }
        return bp
      })
    })
  }
  
  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 bg-indigo-500/20 rounded-lg flex items-center justify-center">
            <FileText className="w-5 h-5 text-indigo-400" />
          </div>
          <h1 className="text-3xl font-bold text-white">Documentation</h1>
        </div>
        <p className="text-gray-400">
          Everything you need to know about verifying agents and integrating with AgentDMV.
        </p>
      </div>
      
      {/* Quick Links */}
      <div className="card p-4 mb-8">
        <div className="flex flex-wrap gap-4">
          <a
            href="/verify.md"
            target="_blank"
            className="inline-flex items-center gap-2 text-indigo-400 hover:text-indigo-300 transition-colors"
          >
            <FileText className="w-4 h-4" />
            View raw verify.md
            <ExternalLink className="w-3 h-3" />
          </a>
          <a
            href="https://github.com/packtman/Agentproof"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 text-indigo-400 hover:text-indigo-300 transition-colors"
          >
            GitHub Repository
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </div>
      
      {/* Documentation Content */}
      <div className="card p-8">
        {loading ? (
          <div className="animate-pulse space-y-4">
            <div className="h-8 bg-gray-800 rounded w-1/3" />
            <div className="h-4 bg-gray-800 rounded w-full" />
            <div className="h-4 bg-gray-800 rounded w-2/3" />
            <div className="h-32 bg-gray-800 rounded w-full mt-4" />
          </div>
        ) : markdown ? (
          <div className="prose prose-invert max-w-none">
            {renderMarkdown(markdown)}
          </div>
        ) : (
          <p className="text-gray-400">Failed to load documentation.</p>
        )}
      </div>
    </div>
  )
}
