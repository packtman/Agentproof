import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import HomePage from './pages/HomePage'
import AgentsPage from './pages/AgentsPage'
import AgentProfilePage from './pages/AgentProfilePage'
import DocsPage from './pages/DocsPage'
import ForAgentsPage from './pages/ForAgentsPage'
import ForPlatformsPage from './pages/ForPlatformsPage'
import PlatformsPage from './pages/PlatformsPage'
import PlatformVerifyPage from './pages/PlatformVerifyPage'
import ClaimPage from './pages/ClaimPage'
import AdminPage from './pages/AdminPage'
import SkillScannerPage from './pages/SkillScannerPage'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<HomePage />} />
        <Route path="agents" element={<AgentsPage />} />
        <Route path="a/:name" element={<AgentProfilePage />} />
        <Route path="for-agents" element={<ForAgentsPage />} />
        <Route path="for-platforms" element={<ForPlatformsPage />} />
        <Route path="docs" element={<DocsPage />} />
        <Route path="platforms" element={<PlatformsPage />} />
        <Route path="platforms/register" element={<PlatformsPage />} />
        <Route path="platforms/verify" element={<PlatformVerifyPage />} />
        <Route path="claim/:token" element={<ClaimPage />} />
        <Route path="skill-scanner" element={<SkillScannerPage />} />
        {/* Admin page - ONLY available if VITE_ADMIN_PATH is set in .env */}
        {import.meta.env.VITE_ADMIN_PATH && (
          <Route path={import.meta.env.VITE_ADMIN_PATH} element={<AdminPage />} />
        )}
      </Route>
    </Routes>
  )
}

export default App
