import { Outlet, Link, useLocation } from 'react-router-dom'
import { ShieldCheck, Bot, FileText, Building2, Github } from 'lucide-react'

export default function Layout() {
  const location = useLocation()
  
  const navItems = [
    { path: '/', label: 'Home', icon: ShieldCheck },
    { path: '/agents', label: 'Agents', icon: Bot },
    { path: '/docs', label: 'Docs', icon: FileText },
    { path: '/platforms', label: 'Platforms', icon: Building2 },
  ]
  
  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-lg sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <Link to="/" className="flex items-center gap-2">
              <div className="w-8 h-8 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-lg flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-white" />
              </div>
              <span className="text-xl font-bold gradient-text">AgentDMV</span>
            </Link>
            
            {/* Navigation */}
            <nav className="hidden md:flex items-center gap-1">
              {navItems.map((item) => {
                const Icon = item.icon
                const isActive = location.pathname === item.path
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                      isActive
                        ? 'bg-gray-800 text-white'
                        : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    {item.label}
                  </Link>
                )
              })}
            </nav>
            
            {/* GitHub Link */}
            <a
              href="https://github.com/packtman/Agentproof"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-4 py-2 text-gray-400 hover:text-white transition-colors"
            >
              <Github className="w-5 h-5" />
              <span className="hidden sm:inline text-sm">GitHub</span>
            </a>
          </div>
        </div>
      </header>
      
      {/* Main Content */}
      <main className="flex-1">
        <Outlet />
      </main>
      
      {/* Footer */}
      <footer className="border-t border-gray-800 py-8 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-gray-500">
              <ShieldCheck className="w-5 h-5" />
              <span>AgentDMV - The DMV for AI Agents</span>
            </div>
            <div className="flex items-center gap-6 text-sm text-gray-500">
              <Link to="/docs" className="hover:text-white transition-colors">Documentation</Link>
              <a href="https://github.com/packtman/Agentproof" className="hover:text-white transition-colors">GitHub</a>
              <span>MIT License</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
