import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Shield, Users, DollarSign, Activity, Database, Bot, Cog, Download, Trash2, Upload, Eye, RefreshCw } from 'lucide-react';
import { toast, Toaster } from 'sonner';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const AdminPanel = () => {
  const navigate = useNavigate();
  const [token, setToken] = useState(localStorage.getItem('admin_token'));
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  
  // Data states
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [revenue, setRevenue] = useState(null);
  const [activityData, setActivityData] = useState(null);
  const [agentStatus, setAgentStatus] = useState(null);

  const login = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${BACKEND_URL}/api/admin/login`, {
        username,
        password
      });
      
      setToken(response.data.token);
      localStorage.setItem('admin_token', response.data.token);
      toast.success('Admin login successful');
    } catch (error) {
      toast.error('Login failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setToken(null);
    localStorage.removeItem('admin_token');
    toast.success('Logged out');
  };

  const fetchData = async (type) => {
    if (!token) return;
    
    try {
      const response = await axios.get(`${BACKEND_URL}/api/admin/data?data_type=${type}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (type === 'users') setUsers(response.data.data || []);
      if (type === 'revenue') setRevenue(response.data);
      if (type === 'activity') setActivityData(response.data);
    } catch (error) {
      if (error.response?.status === 401) {
        logout();
      }
      toast.error('Failed to fetch data');
    }
  };

  const fetchStats = async () => {
    if (!token) return;
    
    try {
      const response = await axios.get(`${BACKEND_URL}/api/admin/data/stats`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setStats(response.data.statistics);
    } catch (error) {
      console.error('Stats error:', error);
    }
  };

  const importSampleData = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${BACKEND_URL}/api/admin/import/sample`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      toast.success(response.data.message);
      await fetchStats();
    } catch (error) {
      toast.error('Import failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const clearTestData = async () => {
    if (!confirm('Are you sure you want to clear all test data?')) return;
    
    setLoading(true);
    try {
      const response = await axios.delete(`${BACKEND_URL}/api/admin/data/clear`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      toast.success(`Cleared ${response.data.deleted} records`);
      await fetchStats();
    } catch (error) {
      toast.error('Clear failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const executeAgent = async (task) => {
    setLoading(true);
    try {
      const response = await axios.post(`${BACKEND_URL}/api/agent/execute`, 
        { task },
        { headers: { Authorization: `Bearer ${token}` }}
      );
      toast.success(`Agent task completed: ${response.data.task}`);
      setAgentStatus(response.data);
    } catch (error) {
      toast.error('Agent execution failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (token && activeTab === 'overview') {
      fetchStats();
    }
  }, [token, activeTab]);

  // Login Screen
  if (!token) {
    return (
      <div className="min-h-screen bg-[#F4F4F5] flex items-center justify-center p-6">
        <Toaster position="top-right" richColors />
        <div className="bg-white border-2 border-[#E4E4E7] p-8 w-full max-w-md">
          <div className="flex items-center gap-3 mb-6">
            <Shield className="w-8 h-8 text-[#0055FF]" />
            <h1 className="font-heading font-black text-2xl">ADMIN LOGIN</h1>
          </div>
          
          <div className="space-y-4 mb-6">
            <div>
              <label className="block font-body font-medium text-sm mb-2">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 focus:outline-none focus:border-[#0055FF]"
                placeholder="admin"
              />
            </div>
            <div>
              <label className="block font-body font-medium text-sm mb-2">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 focus:outline-none focus:border-[#0055FF]"
                placeholder="SecCheck2024!"
                onKeyPress={(e) => e.key === 'Enter' && login()}
              />
            </div>
          </div>

          <button
            onClick={login}
            disabled={loading}
            className="w-full bg-[#0055FF] text-white py-3 font-body font-medium hover:bg-[#0044DD] transition-colors disabled:opacity-50"
          >
            {loading ? 'LOGGING IN...' : 'LOGIN'}
          </button>

          <div className="mt-6 p-4 bg-[#E6F0FF] border border-[#0055FF] text-sm">
            <div className="font-body font-medium mb-2">Default Credentials:</div>
            <div className="font-code text-xs">
              Username: <strong>admin</strong><br/>
              Password: <strong>SecCheck2024!</strong>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Admin Dashboard
  return (
    <div className="min-h-screen bg-[#F4F4F5]">
      <Toaster position="top-right" richColors />
      
      {/* Header */}
      <div className="bg-white border-b-2 border-[#E4E4E7] p-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Shield className="w-8 h-8 text-[#0055FF]" />
            <div>
              <h1 className="font-heading font-black text-2xl">ADMIN PANEL</h1>
              <p className="text-sm text-[#71717A]">Full System Control</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/dashboard')}
              className="btn-outline py-2 px-4 text-sm"
            >
              VIEW SITE
            </button>
            <button
              onClick={logout}
              className="bg-[#FF3333] text-white py-2 px-4 text-sm hover:bg-[#DD2222] transition-colors"
            >
              LOGOUT
            </button>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <div className="bg-white border-b border-[#E4E4E7]">
        <div className="max-w-7xl mx-auto flex gap-0">
          {[
            { id: 'overview', icon: Activity, label: 'OVERVIEW' },
            { id: 'users', icon: Users, label: 'USERS' },
            { id: 'revenue', icon: DollarSign, label: 'REVENUE' },
            { id: 'database', icon: Database, label: 'DATABASE' },
            { id: 'agents', icon: Bot, label: 'AI AGENTS' },
            { id: 'system', icon: Cog, label: 'SYSTEM' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-6 py-4 font-body font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-[#0055FF] text-[#0055FF]'
                  : 'border-transparent text-[#71717A] hover:text-[#09090B]'
              }`}
            >
              <div className="flex items-center gap-2">
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto p-6">
        {/* Overview */}
        {activeTab === 'overview' && stats && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-white border border-[#E4E4E7] p-6">
                <div className="label-uppercase text-xs mb-2">TOTAL RECORDS</div>
                <div className="font-heading font-black text-4xl text-[#0055FF]">
                  {Object.values(stats).reduce((a, b) => a + b, 0)}
                </div>
              </div>
              <div className="bg-white border border-[#E4E4E7] p-6">
                <div className="label-uppercase text-xs mb-2">SOCIAL ACCOUNTS</div>
                <div className="font-heading font-black text-4xl text-[#00CC66]">
                  {stats.social_accounts}
                </div>
              </div>
              <div className="bg-white border border-[#E4E4E7] p-6">
                <div className="label-uppercase text-xs mb-2">BREACH DATA</div>
                <div className="font-heading font-black text-4xl text-[#FF3333]">
                  {stats.breach_data}
                </div>
              </div>
            </div>

            <div className="bg-white border border-[#E4E4E7] p-6">
              <div className="label-uppercase mb-4">QUICK ACTIONS</div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <button
                  onClick={importSampleData}
                  disabled={loading}
                  className="p-4 border-2 border-[#0055FF] hover:bg-[#0055FF] hover:text-white transition-colors flex flex-col items-center gap-2"
                >
                  <Upload className="w-6 h-6" />
                  <span className="text-sm font-medium">IMPORT SAMPLE DATA</span>
                </button>
                <button
                  onClick={clearTestData}
                  disabled={loading}
                  className="p-4 border-2 border-[#FF3333] hover:bg-[#FF3333] hover:text-white transition-colors flex flex-col items-center gap-2"
                >
                  <Trash2 className="w-6 h-6" />
                  <span className="text-sm font-medium">CLEAR TEST DATA</span>
                </button>
                <button
                  onClick={fetchStats}
                  className="p-4 border-2 border-[#00CC66] hover:bg-[#00CC66] hover:text-white transition-colors flex flex-col items-center gap-2"
                >
                  <RefreshCw className="w-6 h-6" />
                  <span className="text-sm font-medium">REFRESH STATS</span>
                </button>
                <button
                  onClick={() => setActiveTab('database')}
                  className="p-4 border-2 border-[#FFCC00] hover:bg-[#FFCC00] transition-colors flex flex-col items-center gap-2"
                >
                  <Eye className="w-6 h-6" />
                  <span className="text-sm font-medium">VIEW DATABASE</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Database Stats */}
        {activeTab === 'database' && stats && (
          <div className="bg-white border border-[#E4E4E7] p-6">
            <div className="label-uppercase mb-4">DATABASE STATISTICS</div>
            <div className="space-y-2">
              {Object.entries(stats).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between py-3 border-b border-[#E4E4E7]">
                  <span className="font-body text-[#09090B]">{key.replace(/_/g, ' ').toUpperCase()}</span>
                  <span className="font-heading font-black text-2xl text-[#0055FF]">{value}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* AI Agents */}
        {activeTab === 'agents' && (
          <div className="space-y-4">
            <div className="bg-white border border-[#E4E4E7] p-6">
              <div className="label-uppercase mb-4">AI AGENT CONTROLS</div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  { task: 'optimize database', label: 'Optimize Database', icon: Database },
                  { task: 'backup database', label: 'Backup Database', icon: Download },
                  { task: 'security scan', label: 'Security Scan', icon: Shield },
                  { task: 'monitor system', label: 'Monitor System', icon: Activity },
                  { task: 'clean maintenance', label: 'Clean & Maintain', icon: Cog }
                ].map((agent, idx) => (
                  <button
                    key={idx}
                    onClick={() => executeAgent(agent.task)}
                    disabled={loading}
                    className="p-6 border-2 border-[#E4E4E7] hover:border-[#0055FF] transition-colors flex items-center gap-4"
                  >
                    <agent.icon className="w-8 h-8 text-[#0055FF]" />
                    <div className="text-left">
                      <div className="font-body font-medium text-[#09090B]">{agent.label}</div>
                      <div className="text-xs text-[#71717A]">Task: {agent.task}</div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {agentStatus && (
              <div className="bg-white border border-[#E4E4E7] p-6">
                <div className="label-uppercase mb-4">LAST AGENT EXECUTION</div>
                <pre className="bg-[#09090B] text-[#00CC66] p-4 text-xs font-code overflow-auto">
                  {JSON.stringify(agentStatus, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}

        {/* System Tab */}
        {activeTab === 'system' && (
          <div className="bg-white border border-[#E4E4E7] p-6">
            <div className="label-uppercase mb-4">SYSTEM INFORMATION</div>
            <div className="space-y-4">
              <div className="p-4 bg-[#F4F4F5] border border-[#E4E4E7]">
                <div className="text-sm font-body font-medium mb-2">Admin Credentials</div>
                <div className="font-code text-xs">
                  Username: <strong>admin</strong><br/>
                  Password: <strong>SecCheck2024!</strong>
                </div>
              </div>
              <div className="p-4 bg-[#F4F4F5] border border-[#E4E4E7]">
                <div className="text-sm font-body font-medium mb-2">API Endpoints</div>
                <div className="font-code text-xs space-y-1">
                  <div>Admin Login: POST /api/admin/login</div>
                  <div>Import Data: POST /api/admin/import/sample</div>
                  <div>Clear Data: DELETE /api/admin/data/clear</div>
                  <div>Stats: GET /api/admin/data/stats</div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminPanel;
