import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Shield, Hash, Globe, Play, Loader2, ChevronDown, ChevronUp, Copy, Check, Mail, AlertTriangle, Eye, Lock, DollarSign, CreditCard } from 'lucide-react';
import { toast, Toaster } from 'sonner';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const Dashboard = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('pentest');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // Pen-test state
  const [targetUrl, setTargetUrl] = useState('');
  const [selectedTests, setSelectedTests] = useState({
    port_scan: true,
    ssl_tls: true,
    security_headers: true,
    xss_detection: false,
    sql_injection: false
  });
  const [pentestResults, setPentestResults] = useState(null);

  // Hash decoder state
  const [hashInput, setHashInput] = useState('');
  const [hashResults, setHashResults] = useState(null);

  // Hash generator state
  const [textInput, setTextInput] = useState('');
  const [generatedHashes, setGeneratedHashes] = useState(null);

  // API test state
  const [apiUrl, setApiUrl] = useState('');
  const [apiMethod, setApiMethod] = useState('GET');
  const [apiResults, setApiResults] = useState(null);

  // Email breach state
  const [emailInput, setEmailInput] = useState('');
  const [breachResults, setBreachResults] = useState(null);

  // Hash cracking state
  const [crackHashInput, setCrackHashInput] = useState('');
  const [crackHashType, setCrackHashType] = useState('MD5');
  const [crackMethod, setCrackMethod] = useState('dictionary');
  const [crackResults, setCrackResults] = useState(null);
  const [sessionHistory, setSessionHistory] = useState([]);

  // Breach details state
  const [detailEmail, setDetailEmail] = useState('');
  const [consentGiven, setConsentGiven] = useState(false);
  const [breachDetails, setBreachDetails] = useState(null);

  // Security audit state
  const [auditEmail, setAuditEmail] = useState('');
  const [auditResults, setAuditResults] = useState(null);
  const [selectedService, setSelectedService] = useState(null);

  // Social media search state
  const [socialQuery, setSocialQuery] = useState('');
  const [socialSearchType, setSocialSearchType] = useState('email');
  const [socialResults, setSocialResults] = useState(null);

  const [expandedSections, setExpandedSections] = useState({});

  const toggleSection = (section) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success('Copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  };

  const runPentest = async () => {
    if (!targetUrl) {
      toast.error('Please enter a target URL');
      return;
    }

    setLoading(true);
    try {
      const tests = Object.keys(selectedTests).filter(key => selectedTests[key]);
      const response = await axios.post(`${API}/pentest/scan`, {
        target_url: targetUrl,
        tests
      });
      setPentestResults(response.data);
      toast.success('Penetration test completed');
    } catch (error) {
      toast.error('Pen-test failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const decodeHash = async () => {
    if (!hashInput) {
      toast.error('Please enter a hash value');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/hash/decode`, {
        hash_value: hashInput
      });
      setHashResults(response.data);
      toast.success('Hash analyzed successfully');
    } catch (error) {
      toast.error('Hash decode failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const generateHashes = async () => {
    if (!textInput) {
      toast.error('Please enter text to hash');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/hash/generate?text=${encodeURIComponent(textInput)}`);
      setGeneratedHashes(response.data);
      toast.success('Hashes generated successfully');
    } catch (error) {
      toast.error('Hash generation failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const testApi = async () => {
    if (!apiUrl) {
      toast.error('Please enter an API endpoint');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/api/test`, {
        endpoint_url: apiUrl,
        method: apiMethod
      });
      setApiResults(response.data);
      toast.success('API test completed');
    } catch (error) {
      toast.error('API test failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const checkEmailBreach = async () => {
    if (!emailInput) {
      toast.error('Please enter an email address');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/breach/check`, {
        email: emailInput
      });
      setBreachResults(response.data);
      
      addToSession({
        type: 'breach_check',
        target: emailInput,
        status: 'completed',
        details: response.data
      });
      
      if (response.data.breaches_found > 0) {
        toast.error(`${response.data.breaches_found} breaches found!`);
      } else {
        toast.success('No breaches detected');
      }
    } catch (error) {
      toast.error('Breach check failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const crackHash = async () => {
    if (!crackHashInput) {
      toast.error('Please enter a hash value');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/hash/crack`, {
        hash_value: crackHashInput,
        hash_type: crackHashType,
        method: crackMethod,
        max_length: crackMethod === 'bruteforce' ? 4 : undefined
      });
      setCrackResults(response.data);
      
      addToSession({
        type: 'hash_crack',
        target: crackHashInput,
        status: response.data.cracked ? 'cracked' : 'failed',
        details: response.data
      });
      
      if (response.data.cracked) {
        toast.success(`Hash cracked! Plaintext: ${response.data.plaintext}`);
      } else {
        toast.error('Unable to crack hash');
      }
    } catch (error) {
      toast.error('Hash cracking failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const addToSession = (item) => {
    setSessionHistory(prev => [{
      ...item,
      timestamp: new Date().toISOString()
    }, ...prev].slice(0, 50));
  };

  const exportSession = async (format) => {
    try {
      const sessionData = {
        exported_at: new Date().toISOString(),
        results: sessionHistory,
        summary: {
          total_activities: sessionHistory.length,
          successful: sessionHistory.filter(h => h.status === 'completed' || h.status === 'cracked').length
        }
      };

      const response = await axios.post(`${API}/session/export`, {
        session_data: sessionData,
        export_format: format
      }, {
        responseType: 'blob'
      });

      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `seccheck_session_${Date.now()}.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      toast.success(`Session exported as ${format.toUpperCase()}`);
    } catch (error) {
      toast.error('Export failed: ' + (error.response?.data?.detail || error.message));
    }
  };

  const getBreachDetails = async () => {
    if (!detailEmail) {
      toast.error('Please enter an email address');
      return;
    }

    if (!consentGiven) {
      toast.error('You must acknowledge ethical use before viewing sensitive data');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/breach/detailed`, {
        email: detailEmail,
        reveal_sensitive: consentGiven
      });
      setBreachDetails(response.data);
      
      addToSession({
        type: 'breach_details',
        target: detailEmail,
        status: 'completed',
        details: { total_records: response.data.total_records }
      });
      
      toast.warning(`${response.data.total_records} breach records found with sensitive data`);
    } catch (error) {
      toast.error('Breach details failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const runSecurityAudit = async () => {
    if (!auditEmail) {
      toast.error('Please enter an email address');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/security/audit`, {
        email: auditEmail,
        include_consultation: true
      });
      setAuditResults(response.data);
      
      addToSession({
        type: 'security_audit',
        target: auditEmail,
        status: 'completed',
        details: { score: response.data.security_score }
      });
      
      toast.success('Security audit completed');
    } catch (error) {
      toast.error('Security audit failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const searchSocialMedia = async () => {
    if (!socialQuery) {
      toast.error('Please enter an email or username');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/social/search`, {
        query: socialQuery,
        search_type: socialSearchType
      });
      setSocialResults(response.data);
      
      addToSession({
        type: 'social_search',
        target: socialQuery,
        status: 'completed',
        details: { accounts_found: response.data.total_accounts }
      });
      
      if (response.data.compromised_count > 0) {
        toast.error(`${response.data.compromised_count} compromised accounts found!`);
      } else {
        toast.success(`${response.data.total_accounts} accounts found - all secure`);
      }
    } catch (error) {
      toast.error('Social media search failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-white">
      <Toaster position="top-right" richColors />
      
      {/* Navigation */}
      <nav className="border-b border-[#E4E4E7] bg-white/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => navigate('/')}>
            <Shield className="w-8 h-8 text-[#0055FF]" />
            <h1 className="font-heading font-black text-2xl tracking-tightest text-[#09090B]">SECCHECK</h1>
          </div>
          <div className="flex items-center gap-4">
            <div className="label-uppercase text-[#71717A]">SESSION: {sessionHistory.length} ITEMS</div>
            <button
              data-testid="export-json-btn"
              onClick={() => exportSession('json')}
              className="btn-outline py-2 px-4 text-sm"
              disabled={sessionHistory.length === 0}
            >
              EXPORT JSON
            </button>
            <button
              data-testid="export-txt-btn"
              onClick={() => exportSession('txt')}
              className="btn-outline py-2 px-4 text-sm"
              disabled={sessionHistory.length === 0}
            >
              EXPORT TXT
            </button>
          </div>
        </div>
      </nav>

      {/* Tabs */}
      <div className="border-b border-[#E4E4E7] bg-white">
        <div className="max-w-7xl mx-auto px-6 flex gap-0">
          <button
            data-testid="tab-pentest"
            onClick={() => setActiveTab('pentest')}
            className={`px-8 py-4 font-body font-medium border-b-2 transition-colors ${
              activeTab === 'pentest'
                ? 'border-[#0055FF] text-[#0055FF]'
                : 'border-transparent text-[#71717A] hover:text-[#09090B]'
            }`}
          >
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4" />
              PENETRATION TEST
            </div>
          </button>
          <button
            data-testid="tab-hash"
            onClick={() => setActiveTab('hash')}
            className={`px-8 py-4 font-body font-medium border-b-2 transition-colors ${
              activeTab === 'hash'
                ? 'border-[#0055FF] text-[#0055FF]'
                : 'border-transparent text-[#71717A] hover:text-[#09090B]'
            }`}
          >
            <div className="flex items-center gap-2">
              <Hash className="w-4 h-4" />
              HASH ANALYSIS
            </div>
          </button>
          <button
            data-testid="tab-api"
            onClick={() => setActiveTab('api')}
            className={`px-8 py-4 font-body font-medium border-b-2 transition-colors ${
              activeTab === 'api'
                ? 'border-[#0055FF] text-[#0055FF]'
                : 'border-transparent text-[#71717A] hover:text-[#09090B]'
            }`}
          >
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4" />
              API TESTING
            </div>
          </button>
          <button
            data-testid="tab-breach"
            onClick={() => setActiveTab('breach')}
            className={`px-8 py-4 font-body font-medium border-b-2 transition-colors ${
              activeTab === 'breach'
                ? 'border-[#0055FF] text-[#0055FF]'
                : 'border-transparent text-[#71717A] hover:text-[#09090B]'
            }`}
          >
            <div className="flex items-center gap-2">
              <Mail className="w-4 h-4" />
              BREACH LOOKUP
            </div>
          </button>
          <button
            data-testid="tab-crack"
            onClick={() => setActiveTab('crack')}
            className={`px-8 py-4 font-body font-medium border-b-2 transition-colors ${
              activeTab === 'crack'
                ? 'border-[#0055FF] text-[#0055FF]'
                : 'border-transparent text-[#71717A] hover:text-[#09090B]'
            }`}
          >
            <div className="flex items-center gap-2">
              <Hash className="w-4 h-4" />
              HASH CRACKER
            </div>
          </button>
          <button
            data-testid="tab-details"
            onClick={() => setActiveTab('details')}
            className={`px-8 py-4 font-body font-medium border-b-2 transition-colors ${
              activeTab === 'details'
                ? 'border-[#0055FF] text-[#0055FF]'
                : 'border-transparent text-[#71717A] hover:text-[#09090B]'
            }`}
          >
            <div className="flex items-center gap-2">
              <Eye className="w-4 h-4" />
              BREACH DETAILS
            </div>
          </button>
          <button
            data-testid="tab-security"
            onClick={() => setActiveTab('security')}
            className={`px-8 py-4 font-body font-medium border-b-2 transition-colors ${
              activeTab === 'security'
                ? 'border-[#0055FF] text-[#0055FF]'
                : 'border-transparent text-[#71717A] hover:text-[#09090B]'
            }`}
          >
            <div className="flex items-center gap-2">
              <DollarSign className="w-4 h-4" />
              SECURITY SERVICES
            </div>
          </button>
          <button
            data-testid="tab-social"
            onClick={() => setActiveTab('social')}
            className={`px-8 py-4 font-body font-medium border-b-2 transition-colors ${
              activeTab === 'social'
                ? 'border-[#0055FF] text-[#0055FF]'
                : 'border-transparent text-[#71717A] hover:text-[#09090B]'
            }`}
          >
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4" />
              SOCIAL MEDIA
            </div>
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto p-6">
        {/* Penetration Testing */}
        {activeTab === 'pentest' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-px bg-[#E4E4E7]">
            {/* Input Panel */}
            <div className="lg:col-span-5 bg-white p-8">
              <div className="label-uppercase mb-6">CONFIGURATION</div>
              
              <div className="mb-6">
                <label className="block font-body font-medium text-[#09090B] mb-2">
                  Target URL
                </label>
                <input
                  data-testid="pentest-url-input"
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-body focus:outline-none focus:border-[#0055FF]"
                />
              </div>

              <div className="mb-6">
                <label className="block font-body font-medium text-[#09090B] mb-4">
                  Select Tests
                </label>
                <div className="space-y-3">
                  {Object.keys(selectedTests).map((test) => (
                    <label key={test} className="flex items-center gap-3 cursor-pointer">
                      <input
                        data-testid={`test-${test}`}
                        type="checkbox"
                        checked={selectedTests[test]}
                        onChange={(e) =>
                          setSelectedTests({ ...selectedTests, [test]: e.target.checked })
                        }
                        className="w-5 h-5 border-2 border-[#E4E4E7] accent-[#0055FF]"
                      />
                      <span className="font-body text-[#09090B]">
                        {test.replace(/_/g, ' ').toUpperCase()}
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              <button
                data-testid="run-pentest-btn"
                onClick={runPentest}
                disabled={loading}
                className="w-full btn-primary flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    SCANNING...
                  </>
                ) : (
                  <>
                    <Play className="w-5 h-5" />
                    RUN PENETRATION TEST
                  </>
                )}
              </button>
            </div>

            {/* Results Panel */}
            <div className="lg:col-span-7 bg-white p-8">
              <div className="label-uppercase mb-6">RESULTS</div>
              
              {!pentestResults && (
                <div className="flex items-center justify-center h-64 text-[#71717A] font-body">
                  No scan results yet. Configure and run a test.
                </div>
              )}

              {pentestResults && (
                <div className="space-y-px bg-[#E4E4E7]">
                  {Object.keys(pentestResults.results).map((testName) => {
                    const result = pentestResults.results[testName];
                    return (
                      <div key={testName} className="bg-white">
                        <button
                          data-testid={`result-${testName}`}
                          onClick={() => toggleSection(testName)}
                          className="w-full px-6 py-4 flex items-center justify-between hover:bg-[#F4F4F5] transition-colors"
                        >
                          <div className="flex items-center gap-3">
                            <span className="font-body font-medium text-[#09090B]">
                              {testName.replace(/_/g, ' ').toUpperCase()}
                            </span>
                            <span className={`status-badge ${
                              result.status === 'completed' ? 'status-success' :
                              result.status === 'error' ? 'status-error' : 'status-warning'
                            }`}>
                              {result.status}
                            </span>
                          </div>
                          {expandedSections[testName] ? (
                            <ChevronUp className="w-5 h-5 text-[#71717A]" />
                          ) : (
                            <ChevronDown className="w-5 h-5 text-[#71717A]" />
                          )}
                        </button>
                        
                        {expandedSections[testName] && (
                          <div className="px-6 pb-6 border-t border-[#E4E4E7]">
                            <pre className="hash-display mt-4 text-xs overflow-x-auto">
                              {JSON.stringify(result, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Hash Analysis */}
        {activeTab === 'hash' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-px bg-[#E4E4E7]">
            {/* Hash Decoder */}
            <div className="bg-white p-8">
              <div className="label-uppercase mb-6">HASH DECODER</div>
              
              <div className="mb-6">
                <label className="block font-body font-medium text-[#09090B] mb-2">
                  Hash Value
                </label>
                <textarea
                  data-testid="hash-input"
                  value={hashInput}
                  onChange={(e) => setHashInput(e.target.value)}
                  placeholder="Enter hash to identify..."
                  className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-code text-sm focus:outline-none focus:border-[#0055FF] h-32"
                />
              </div>

              <button
                data-testid="decode-hash-btn"
                onClick={decodeHash}
                disabled={loading}
                className="w-full btn-primary mb-6"
              >
                {loading ? 'ANALYZING...' : 'ANALYZE HASH'}
              </button>

              {hashResults && (
                <div className="space-y-4">
                  <div className="border border-[#E4E4E7] p-4">
                    <div className="label-uppercase mb-2">DETECTED TYPE</div>
                    <div className="font-heading font-black text-2xl text-[#0055FF]">
                      {hashResults.detected_type}
                    </div>
                  </div>

                  {hashResults.possible_types.length > 0 && (
                    <div className="border border-[#E4E4E7] p-4">
                      <div className="label-uppercase mb-2">POSSIBLE TYPES</div>
                      <div className="flex flex-wrap gap-2">
                        {hashResults.possible_types.map((type) => (
                          <span
                            key={type}
                            className="px-3 py-1 bg-[#F4F4F5] border border-[#E4E4E7] font-code text-xs"
                          >
                            {type}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="border border-[#E4E4E7] p-4">
                    <div className="label-uppercase mb-2">STATUS</div>
                    <div className="font-body text-[#09090B]">{hashResults.message}</div>
                  </div>
                </div>
              )}
            </div>

            {/* Hash Generator */}
            <div className="bg-white p-8">
              <div className="label-uppercase mb-6">HASH GENERATOR</div>
              
              <div className="mb-6">
                <label className="block font-body font-medium text-[#09090B] mb-2">
                  Text to Hash
                </label>
                <textarea
                  data-testid="text-input"
                  value={textInput}
                  onChange={(e) => setTextInput(e.target.value)}
                  placeholder="Enter text to generate hashes..."
                  className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-body text-sm focus:outline-none focus:border-[#0055FF] h-32"
                />
              </div>

              <button
                data-testid="generate-hash-btn"
                onClick={generateHashes}
                disabled={loading}
                className="w-full btn-primary mb-6"
              >
                {loading ? 'GENERATING...' : 'GENERATE ALL HASHES'}
              </button>

              {generatedHashes && (
                <div className="space-y-3 max-h-96 overflow-y-auto">
                  {Object.entries(generatedHashes.hashes).map(([type, hash]) => (
                    <div key={type} className="border border-[#E4E4E7] p-3">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-body font-medium text-[#09090B] text-sm">{type}</span>
                        <button
                          data-testid={`copy-${type}`}
                          onClick={() => copyToClipboard(hash)}
                          className="p-1 hover:bg-[#F4F4F5] transition-colors"
                        >
                          {copied ? (
                            <Check className="w-4 h-4 text-[#00CC66]" />
                          ) : (
                            <Copy className="w-4 h-4 text-[#71717A]" />
                          )}
                        </button>
                      </div>
                      <div className="font-code text-xs text-[#71717A] break-all">{hash}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* API Testing */}
        {activeTab === 'api' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-px bg-[#E4E4E7]">
            {/* Input Panel */}
            <div className="lg:col-span-5 bg-white p-8">
              <div className="label-uppercase mb-6">API ENDPOINT TEST</div>
              
              <div className="mb-6">
                <label className="block font-body font-medium text-[#09090B] mb-2">
                  API Endpoint URL
                </label>
                <input
                  data-testid="api-url-input"
                  type="text"
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  placeholder="https://api.example.com/v1/users"
                  className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-body focus:outline-none focus:border-[#0055FF]"
                />
              </div>

              <div className="mb-6">
                <label className="block font-body font-medium text-[#09090B] mb-2">
                  HTTP Method
                </label>
                <select
                  data-testid="api-method-select"
                  value={apiMethod}
                  onChange={(e) => setApiMethod(e.target.value)}
                  className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-body focus:outline-none focus:border-[#0055FF]"
                >
                  <option>GET</option>
                  <option>POST</option>
                  <option>PUT</option>
                  <option>DELETE</option>
                </select>
              </div>

              <button
                data-testid="test-api-btn"
                onClick={testApi}
                disabled={loading}
                className="w-full btn-primary flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    TESTING...
                  </>
                ) : (
                  <>
                    <Play className="w-5 h-5" />
                    TEST API ENDPOINT
                  </>
                )}
              </button>
            </div>

            {/* Results Panel */}
            <div className="lg:col-span-7 bg-white p-8">
              <div className="label-uppercase mb-6">API TEST RESULTS</div>
              
              {!apiResults && (
                <div className="flex items-center justify-center h-64 text-[#71717A] font-body">
                  No API test results yet. Enter an endpoint and run a test.
                </div>
              )}

              {apiResults && (
                <div className="space-y-4">
                  <div className="border border-[#E4E4E7] p-4">
                    <div className="label-uppercase mb-2">STATUS CODE</div>
                    <div className={`font-heading font-black text-3xl ${
                      apiResults.status_code >= 200 && apiResults.status_code < 300
                        ? 'text-[#00CC66]'
                        : apiResults.status_code >= 400
                        ? 'text-[#FF3333]'
                        : 'text-[#FFCC00]'
                    }`}>
                      {apiResults.status_code}
                    </div>
                  </div>

                  <div className="border border-[#E4E4E7] p-4">
                    <div className="label-uppercase mb-3">SECURITY HEADERS</div>
                    <div className="space-y-2">
                      {Object.entries(apiResults.security_headers).map(([key, value]) => (
                        <div key={key} className="flex items-center justify-between py-2 border-b border-[#E4E4E7] last:border-0">
                          <span className="font-code text-xs text-[#71717A]">{key}</span>
                          <span className="font-code text-xs text-[#09090B]">{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {apiResults.issues && apiResults.issues.length > 0 && (
                    <div className="border-2 border-[#FF3333] p-4">
                      <div className="label-uppercase mb-3 text-[#FF3333]">SECURITY ISSUES</div>
                      <ul className="space-y-2">
                        {apiResults.issues.map((issue, idx) => (
                          <li key={idx} className="font-body text-sm text-[#09090B] flex items-start gap-2">
                            <span className="text-[#FF3333]">•</span>
                            {issue}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Email Breach Lookup */}
        {activeTab === 'breach' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-px bg-[#E4E4E7]">
            {/* Input Panel */}
            <div className="lg:col-span-5 bg-white p-8">
              <div className="label-uppercase mb-6">EMAIL BREACH CHECKER</div>
              
              <div className="mb-6">
                <label className="block font-body font-medium text-[#09090B] mb-2">
                  Email Address
                </label>
                <input
                  data-testid="email-input"
                  type="email"
                  value={emailInput}
                  onChange={(e) => setEmailInput(e.target.value)}
                  placeholder="user@example.com"
                  className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-body focus:outline-none focus:border-[#0055FF]"
                />
              </div>

              <div className="mb-6 p-4 bg-[#FFF5E6] border border-[#FFCC00]">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-5 h-5 text-[#FFCC00] flex-shrink-0 mt-0.5" />
                  <div className="text-sm text-[#09090B] font-body">
                    This tool checks if your email has been compromised in known data breaches.
                    Your email is not stored or shared.
                  </div>
                </div>
              </div>

              <button
                data-testid="check-breach-btn"
                onClick={checkEmailBreach}
                disabled={loading}
                className="w-full btn-primary flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    CHECKING...
                  </>
                ) : (
                  <>
                    <Play className="w-5 h-5" />
                    CHECK BREACHES
                  </>
                )}
              </button>
            </div>

            {/* Results Panel */}
            <div className="lg:col-span-7 bg-white p-8">
              <div className="label-uppercase mb-6">BREACH RESULTS</div>
              
              {!breachResults && (
                <div className="flex items-center justify-center h-64 text-[#71717A] font-body">
                  Enter an email address to check for data breaches.
                </div>
              )}

              {breachResults && (
                <div className="space-y-4">
                  {/* Risk Level Banner */}
                  <div className={`p-6 border-2 ${
                    breachResults.risk_level === 'low' ? 'bg-[#E6F7EE] border-[#00CC66]' :
                    breachResults.risk_level === 'medium' ? 'bg-[#FFF5E6] border-[#FFCC00]' :
                    'bg-[#FFE6E6] border-[#FF3333]'
                  }`}>
                    <div className="flex items-center gap-3 mb-3">
                      {breachResults.risk_level === 'low' ? (
                        <Shield className="w-8 h-8 text-[#00CC66]" />
                      ) : breachResults.risk_level === 'medium' ? (
                        <AlertTriangle className="w-8 h-8 text-[#FFCC00]" />
                      ) : (
                        <AlertTriangle className="w-8 h-8 text-[#FF3333]" />
                      )}
                      <div>
                        <div className="font-heading font-black text-2xl text-[#09090B] uppercase">
                          {breachResults.risk_level} RISK
                        </div>
                        <div className="font-body text-sm text-[#71717A]">
                          {breachResults.breaches_found} {breachResults.breaches_found === 1 ? 'breach' : 'breaches'} detected
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Breach Details */}
                  {breachResults.breach_data && breachResults.breach_data.length > 0 && (
                    <div className="border border-[#E4E4E7]">
                      <div className="bg-[#F4F4F5] px-6 py-3 border-b border-[#E4E4E7]">
                        <div className="label-uppercase">BREACHES FOUND</div>
                      </div>
                      <div className="divide-y divide-[#E4E4E7]">
                        {breachResults.breach_data.map((breach, idx) => (
                          <div key={idx} className="p-4">
                            <div className="flex items-start justify-between mb-2">
                              <div className="font-body font-medium text-[#09090B]">
                                {breach.name}
                              </div>
                              <span className={`status-badge ${
                                breach.severity === 'critical' ? 'status-error' :
                                breach.severity === 'high' ? 'status-warning' :
                                'bg-[#FFCC00] text-[#09090B] border-[#FFCC00]'
                              }`}>
                                {breach.severity}
                              </span>
                            </div>
                            <div className="text-sm text-[#71717A] font-body mb-2">
                              Date: {breach.date} • Records: {breach.records}
                            </div>
                            {breach.data_classes && (
                              <div className="flex flex-wrap gap-2 mt-2">
                                {breach.data_classes.map((dataClass, i) => (
                                  <span
                                    key={i}
                                    className="px-2 py-1 bg-[#F4F4F5] border border-[#E4E4E7] text-xs font-code"
                                  >
                                    {dataClass}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recommendations */}
                  <div className="border border-[#E4E4E7]">
                    <div className="bg-[#F4F4F5] px-6 py-3 border-b border-[#E4E4E7]">
                      <div className="label-uppercase">RECOMMENDATIONS</div>
                    </div>
                    <div className="p-6">
                      <ul className="space-y-3">
                        {breachResults.recommendations.map((rec, idx) => (
                          <li key={idx} className="flex items-start gap-3 font-body text-[#09090B]">
                            <span className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-white text-xs font-bold ${
                              breachResults.risk_level === 'high' ? 'bg-[#FF3333]' :
                              breachResults.risk_level === 'medium' ? 'bg-[#FFCC00]' :
                              'bg-[#00CC66]'
                            }`}>
                              {idx + 1}
                            </span>
                            <span>{rec}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Hash Cracker */}
        {activeTab === 'crack' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-px bg-[#E4E4E7]">
            {/* Input Panel */}
            <div className="lg:col-span-5 bg-white p-8">
              <div className="label-uppercase mb-6">HASH CRACKING ENGINE</div>
              
              <div className="mb-6">
                <label className="block font-body font-medium text-[#09090B] mb-2">
                  Hash Value
                </label>
                <textarea
                  data-testid="crack-hash-input"
                  value={crackHashInput}
                  onChange={(e) => setCrackHashInput(e.target.value)}
                  placeholder="Enter hash to crack..."
                  className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-code text-sm focus:outline-none focus:border-[#0055FF] h-32"
                />
              </div>

              <div className="mb-6">
                <label className="block font-body font-medium text-[#09090B] mb-2">
                  Hash Type
                </label>
                <select
                  data-testid="crack-hash-type-select"
                  value={crackHashType}
                  onChange={(e) => setCrackHashType(e.target.value)}
                  className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-body focus:outline-none focus:border-[#0055FF]"
                >
                  <option value="MD5">MD5</option>
                  <option value="SHA-256">SHA-256</option>
                  <option value="SHA-512">SHA-512</option>
                  <option value="SHA3-256">SHA3-256</option>
                  <option value="SHA3-512">SHA3-512</option>
                  <option value="BLAKE2B">BLAKE2b</option>
                  <option value="BLAKE2S">BLAKE2s</option>
                  <option value="NTLM">NTLM</option>
                </select>
              </div>

              <div className="mb-6">
                <label className="block font-body font-medium text-[#09090B] mb-2">
                  Cracking Method
                </label>
                <select
                  data-testid="crack-method-select"
                  value={crackMethod}
                  onChange={(e) => setCrackMethod(e.target.value)}
                  className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-body focus:outline-none focus:border-[#0055FF]"
                >
                  <option value="dictionary">Dictionary Attack</option>
                  <option value="bruteforce">Brute Force (Max 4 chars)</option>
                </select>
              </div>

              <div className="mb-6 p-4 bg-[#FFE6E6] border border-[#FF3333]">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-5 h-5 text-[#FF3333] flex-shrink-0 mt-0.5" />
                  <div className="text-sm text-[#09090B] font-body">
                    <strong>ETHICAL USE ONLY:</strong> Only crack hashes you own or have permission to test.
                    Unauthorized password cracking is illegal.
                  </div>
                </div>
              </div>

              <button
                data-testid="crack-hash-btn"
                onClick={crackHash}
                disabled={loading}
                className="w-full btn-primary flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    CRACKING...
                  </>
                ) : (
                  <>
                    <Play className="w-5 h-5" />
                    START CRACKING
                  </>
                )}
              </button>
            </div>

            {/* Results Panel */}
            <div className="lg:col-span-7 bg-white p-8">
              <div className="label-uppercase mb-6">CRACKING RESULTS</div>
              
              {!crackResults && (
                <div className="flex items-center justify-center h-64 text-[#71717A] font-body">
                  Configure hash parameters and start cracking.
                </div>
              )}

              {crackResults && (
                <div className="space-y-4">
                  {/* Status Banner */}
                  <div className={`p-6 border-2 ${
                    crackResults.cracked 
                      ? 'bg-[#E6F7EE] border-[#00CC66]' 
                      : 'bg-[#FFE6E6] border-[#FF3333]'
                  }`}>
                    <div className="flex items-center gap-3 mb-3">
                      {crackResults.cracked ? (
                        <Check className="w-8 h-8 text-[#00CC66]" />
                      ) : (
                        <AlertTriangle className="w-8 h-8 text-[#FF3333]" />
                      )}
                      <div>
                        <div className="font-heading font-black text-2xl text-[#09090B] uppercase">
                          {crackResults.cracked ? 'HASH CRACKED' : 'CRACK FAILED'}
                        </div>
                        <div className="font-body text-sm text-[#71717A]">
                          {crackResults.attempts.toLocaleString()} attempts in {crackResults.time_taken}s
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Hash Info */}
                  <div className="border border-[#E4E4E7] p-4">
                    <div className="label-uppercase mb-2">HASH TYPE</div>
                    <div className="font-heading font-black text-xl text-[#0055FF]">
                      {crackResults.hash_type}
                    </div>
                  </div>

                  <div className="border border-[#E4E4E7] p-4">
                    <div className="label-uppercase mb-2">METHOD USED</div>
                    <div className="font-body text-[#09090B] capitalize">
                      {crackResults.method_used.replace('_', ' ')}
                    </div>
                  </div>

                  {/* Plaintext Result */}
                  {crackResults.cracked && crackResults.plaintext && (
                    <div className="border-2 border-[#00CC66] p-6 bg-[#E6F7EE]">
                      <div className="label-uppercase mb-3 text-[#00CC66]">RECOVERED PLAINTEXT</div>
                      <div className="flex items-center justify-between gap-4">
                        <div className="font-code text-2xl font-bold text-[#09090B] break-all">
                          {crackResults.plaintext}
                        </div>
                        <button
                          data-testid="copy-plaintext-btn"
                          onClick={() => copyToClipboard(crackResults.plaintext)}
                          className="flex-shrink-0 p-2 hover:bg-white border border-[#00CC66] transition-colors"
                        >
                          {copied ? (
                            <Check className="w-5 h-5 text-[#00CC66]" />
                          ) : (
                            <Copy className="w-5 h-5 text-[#00CC66]" />
                          )}
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Stats */}
                  <div className="grid grid-cols-2 gap-px bg-[#E4E4E7]">
                    <div className="bg-white p-4">
                      <div className="label-uppercase mb-2">ATTEMPTS</div>
                      <div className="font-heading font-black text-3xl text-[#0055FF]">
                        {crackResults.attempts.toLocaleString()}
                      </div>
                    </div>
                    <div className="bg-white p-4">
                      <div className="label-uppercase mb-2">TIME TAKEN</div>
                      <div className="font-heading font-black text-3xl text-[#FF3333]">
                        {crackResults.time_taken}s
                      </div>
                    </div>
                  </div>

                  {!crackResults.cracked && (
                    <div className="border border-[#E4E4E7] p-6 bg-[#F4F4F5]">
                      <div className="label-uppercase mb-3">SUGGESTIONS</div>
                      <ul className="space-y-2 text-sm text-[#09090B] font-body">
                        <li>• Try switching to bruteforce method for short passwords</li>
                        <li>• The password may not be in the common dictionary</li>
                        <li>• Consider using external tools for advanced cracking</li>
                        <li>• Increase max_length for brute force (warning: computationally expensive)</li>
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Breach Details Viewer */}
        {activeTab === 'details' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-px bg-[#E4E4E7]">
            {/* Input Panel */}
            <div className="lg:col-span-5 bg-white p-8">
              <div className="label-uppercase mb-6">DETAILED BREACH ANALYSIS</div>
              
              <div className="mb-6">
                <label className="block font-body font-medium text-[#09090B] mb-2">
                  Email Address
                </label>
                <input
                  data-testid="detail-email-input"
                  type="email"
                  value={detailEmail}
                  onChange={(e) => setDetailEmail(e.target.value)}
                  placeholder="user@example.com"
                  className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-body focus:outline-none focus:border-[#0055FF]"
                />
              </div>

              <div className="mb-6 p-6 bg-[#FFE6E6] border-2 border-[#FF3333]">
                <div className="flex items-start gap-3 mb-4">
                  <AlertTriangle className="w-6 h-6 text-[#FF3333] flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="font-heading font-black text-lg text-[#FF3333] mb-2">
                      CRITICAL WARNING
                    </div>
                    <div className="text-sm text-[#09090B] font-body mb-3">
                      This feature reveals SENSITIVE DATA including passwords, phone numbers, and personal information from data breaches.
                    </div>
                    <ul className="text-xs text-[#09090B] font-body space-y-1 mb-4">
                      <li>• Only use for accounts you own or have authorization to investigate</li>
                      <li>• Data is for security assessment purposes ONLY</li>
                      <li>• Unauthorized access or misuse is illegal</li>
                      <li>• All queries are logged for legal compliance</li>
                    </ul>
                  </div>
                </div>
                
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    data-testid="consent-checkbox"
                    type="checkbox"
                    checked={consentGiven}
                    onChange={(e) => setConsentGiven(e.target.checked)}
                    className="w-5 h-5 border-2 border-[#FF3333] accent-[#FF3333] mt-0.5"
                  />
                  <span className="text-sm text-[#09090B] font-body">
                    I confirm I have legal authorization to view this data and will use it ethically for security purposes only
                  </span>
                </label>
              </div>

              <button
                data-testid="reveal-breach-btn"
                onClick={getBreachDetails}
                disabled={loading || !consentGiven}
                className="w-full btn-primary flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    ANALYZING...
                  </>
                ) : (
                  <>
                    <Eye className="w-5 h-5" />
                    REVEAL BREACH DATA
                  </>
                )}
              </button>
            </div>

            {/* Results Panel */}
            <div className="lg:col-span-7 bg-white p-8">
              <div className="label-uppercase mb-6">EXPOSED DATA</div>
              
              {!breachDetails && (
                <div className="flex items-center justify-center h-64 text-[#71717A] font-body text-center px-8">
                  Acknowledge ethical use terms and enter email to view detailed breach data.
                </div>
              )}

              {breachDetails && (
                <div className="space-y-4">
                  {/* Summary */}
                  <div className="border-2 border-[#FF3333] bg-[#FFE6E6] p-6">
                    <div className="flex items-center gap-3 mb-3">
                      <Lock className="w-8 h-8 text-[#FF3333]" />
                      <div>
                        <div className="font-heading font-black text-2xl text-[#09090B]">
                          {breachDetails.total_records} BREACH RECORDS
                        </div>
                        <div className="font-body text-sm text-[#71717A] uppercase">
                          Severity: {breachDetails.severity}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Exposed Data Summary */}
                  <div className="grid grid-cols-2 gap-px bg-[#E4E4E7]">
                    <div className="bg-white p-4">
                      <div className="label-uppercase mb-2">PASSWORDS</div>
                      <div className="font-heading font-black text-3xl text-[#FF3333]">
                        {breachDetails.exposed_data.passwords}
                      </div>
                    </div>
                    <div className="bg-white p-4">
                      <div className="label-uppercase mb-2">PHONE NUMBERS</div>
                      <div className="font-heading font-black text-3xl text-[#FFCC00]">
                        {breachDetails.exposed_data.phones}
                      </div>
                    </div>
                  </div>

                  {/* Compromised Passwords */}
                  {breachDetails.compromised_passwords && breachDetails.compromised_passwords.length > 0 && (
                    <div className="border border-[#E4E4E7]">
                      <div className="bg-[#FFE6E6] px-6 py-3 border-b border-[#FF3333]">
                        <div className="label-uppercase text-[#FF3333]">COMPROMISED PASSWORDS</div>
                      </div>
                      <div className="divide-y divide-[#E4E4E7]">
                        {breachDetails.compromised_passwords.map((pwd, idx) => (
                          <div key={idx} className="p-4">
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-body font-medium text-[#09090B]">{pwd.source}</span>
                              <span className={`status-badge ${pwd.cracked ? 'status-error' : 'status-warning'}`}>
                                {pwd.cracked ? 'CRACKED' : 'ENCRYPTED'}
                              </span>
                            </div>
                            <div className="hash-display mb-2 text-xs">
                              Hash: {pwd.password_hash}
                            </div>
                            {pwd.cracked && pwd.plaintext && (
                              <div className="bg-[#FFE6E6] border border-[#FF3333] p-3 flex items-center justify-between">
                                <div>
                                  <div className="text-xs label-uppercase text-[#FF3333] mb-1">PLAINTEXT PASSWORD</div>
                                  <div className="font-code font-bold text-[#09090B]">{pwd.plaintext}</div>
                                </div>
                                <button
                                  onClick={() => copyToClipboard(pwd.plaintext)}
                                  className="p-2 hover:bg-white transition-colors"
                                >
                                  {copied ? <Check className="w-4 h-4 text-[#00CC66]" /> : <Copy className="w-4 h-4 text-[#FF3333]" />}
                                </button>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Phone Records */}
                  {breachDetails.phone_records && breachDetails.phone_records.length > 0 && (
                    <div className="border border-[#E4E4E7] p-6">
                      <div className="label-uppercase mb-3">EXPOSED PHONE NUMBERS</div>
                      <div className="space-y-2">
                        {breachDetails.phone_records.map((phone, idx) => (
                          <div key={idx} className="flex items-center justify-between py-2 border-b border-[#E4E4E7] last:border-0">
                            <span className="font-code text-[#09090B]">{phone}</span>
                            <button
                              onClick={() => copyToClipboard(phone)}
                              className="p-1 hover:bg-[#F4F4F5] transition-colors"
                            >
                              <Copy className="w-4 h-4 text-[#71717A]" />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Personal Info */}
                  {breachDetails.personal_info && (
                    <div className="border border-[#E4E4E7] p-6">
                      <div className="label-uppercase mb-3">PERSONAL INFORMATION</div>
                      <div className="space-y-3 text-sm">
                        {breachDetails.personal_info.full_name && (
                          <div className="flex justify-between">
                            <span className="text-[#71717A]">Name:</span>
                            <span className="font-body text-[#09090B]">{breachDetails.personal_info.full_name}</span>
                          </div>
                        )}
                        {breachDetails.personal_info.date_of_birth && (
                          <div className="flex justify-between">
                            <span className="text-[#71717A]">DOB:</span>
                            <span className="font-body text-[#09090B]">{breachDetails.personal_info.date_of_birth}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {breachDetails.requires_premium && (
                    <div className="bg-[#0055FF] text-white p-6">
                      <div className="flex items-center gap-3 mb-3">
                        <CreditCard className="w-6 h-6" />
                        <div className="font-heading font-black text-xl">UPGRADE FOR FULL REPORT</div>
                      </div>
                      <p className="text-white/90 mb-4 text-sm">
                        Get complete breach analysis with remediation steps and ongoing monitoring.
                      </p>
                      <button
                        onClick={() => setActiveTab('security')}
                        className="bg-white text-[#0055FF] px-6 py-2 font-body font-medium hover:bg-white/90 transition-colors"
                      >
                        VIEW SECURITY SERVICES
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Security Services */}
        {activeTab === 'security' && (
          <div className="max-w-6xl mx-auto">
            <div className="mb-8 p-8 bg-white border border-[#E4E4E7]">
              <div className="label-uppercase mb-4">SECURITY AUDIT & CONSULTATION</div>
              <p className="text-[#71717A] font-body mb-6">
                Get professional security assessment and personalized recommendations to protect your digital presence.
              </p>
              
              <div className="flex gap-4 mb-6">
                <input
                  data-testid="audit-email-input"
                  type="email"
                  value={auditEmail}
                  onChange={(e) => setAuditEmail(e.target.value)}
                  placeholder="your@email.com"
                  className="flex-1 px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-body focus:outline-none focus:border-[#0055FF]"
                />
                <button
                  data-testid="run-audit-btn"
                  onClick={runSecurityAudit}
                  disabled={loading}
                  className="btn-primary px-8 flex items-center gap-2"
                >
                  {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Shield className="w-5 h-5" />}
                  RUN AUDIT
                </button>
              </div>

              {auditResults && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-6 border-2 border-[#0055FF] bg-[#E6F0FF]">
                    <div>
                      <div className="label-uppercase text-[#0055FF] mb-1">SECURITY SCORE</div>
                      <div className="font-heading font-black text-5xl text-[#0055FF]">
                        {auditResults.security_score}/100
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="label-uppercase text-[#71717A] mb-1">VULNERABILITIES</div>
                      <div className="font-heading font-black text-3xl text-[#FF3333]">
                        {auditResults.vulnerabilities.length}
                      </div>
                    </div>
                  </div>

                  {/* Detailed Findings - All Accounts */}
                  {auditResults.detailed_findings && (
                    <div className="border border-[#E4E4E7]">
                      <div className="bg-[#F4F4F5] px-6 py-3 border-b border-[#E4E4E7]">
                        <div className="label-uppercase">ASSOCIATED ACCOUNTS & CREDENTIALS</div>
                      </div>
                      <div className="p-6">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                          <div className="bg-[#E6F0FF] border border-[#0055FF] p-4">
                            <div className="label-uppercase text-xs text-[#0055FF] mb-2">TOTAL ACCOUNTS</div>
                            <div className="font-heading font-black text-3xl text-[#0055FF]">
                              {auditResults.detailed_findings.total_accounts_analyzed}
                            </div>
                          </div>
                          <div className="bg-[#FFE6E6] border border-[#FF3333] p-4">
                            <div className="label-uppercase text-xs text-[#FF3333] mb-2">COMPROMISED</div>
                            <div className="font-heading font-black text-3xl text-[#FF3333]">
                              {auditResults.detailed_findings.accounts_with_exposed_data.filter(a => a.compromised).length}
                            </div>
                          </div>
                          <div className="bg-[#FFF5E6] border border-[#FFCC00] p-4">
                            <div className="label-uppercase text-xs text-[#FFCC00] mb-2">LINKED EMAILS</div>
                            <div className="font-heading font-black text-3xl text-[#FFCC00]">
                              {auditResults.detailed_findings.all_linked_emails.length}
                            </div>
                          </div>
                        </div>

                        {/* Compromised Credentials Table */}
                        <div className="border border-[#E4E4E7] mb-6">
                          <div className="bg-[#FFE6E6] px-4 py-2 border-b border-[#FF3333]">
                            <div className="label-uppercase text-xs text-[#FF3333]">EXPOSED CREDENTIALS</div>
                          </div>
                          <div className="overflow-x-auto">
                            <table className="w-full text-sm">
                              <thead className="bg-[#F4F4F5] border-b border-[#E4E4E7]">
                                <tr>
                                  <th className="px-4 py-3 text-left font-body font-medium text-[#09090B] uppercase text-xs">Platform</th>
                                  <th className="px-4 py-3 text-left font-body font-medium text-[#09090B] uppercase text-xs">Username</th>
                                  <th className="px-4 py-3 text-left font-body font-medium text-[#09090B] uppercase text-xs">Email</th>
                                  <th className="px-4 py-3 text-left font-body font-medium text-[#09090B] uppercase text-xs">Password</th>
                                  <th className="px-4 py-3 text-left font-body font-medium text-[#09090B] uppercase text-xs">2FA</th>
                                  <th className="px-4 py-3 text-left font-body font-medium text-[#09090B] uppercase text-xs">Status</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-[#E4E4E7]">
                                {auditResults.detailed_findings.compromised_credentials.map((cred, idx) => (
                                  <tr key={idx} className={cred.compromised ? 'bg-[#FFE6E6]' : 'bg-white'}>
                                    <td className="px-4 py-3 font-body text-[#09090B]">{cred.platform}</td>
                                    <td className="px-4 py-3 font-code text-xs">{cred.username}</td>
                                    <td className="px-4 py-3 font-code text-xs">{cred.email}</td>
                                    <td className="px-4 py-3">
                                      {cred.password_plaintext ? (
                                        <div className="flex items-center gap-2">
                                          <span className="font-code text-xs font-bold text-[#FF3333]">{cred.password_plaintext}</span>
                                          <button
                                            onClick={() => copyToClipboard(cred.password_plaintext)}
                                            className="p-1 hover:bg-white transition-colors"
                                          >
                                            {copied ? <Check className="w-3 h-3 text-[#00CC66]" /> : <Copy className="w-3 h-3 text-[#71717A]" />}
                                          </button>
                                        </div>
                                      ) : (
                                        <span className="text-xs text-[#71717A]">Not exposed</span>
                                      )}
                                    </td>
                                    <td className="px-4 py-3">
                                      {cred['2fa_status'] ? (
                                        <span className="text-[#00CC66] text-xs">✓ Enabled</span>
                                      ) : (
                                        <span className="text-[#FF3333] text-xs">✗ Disabled</span>
                                      )}
                                    </td>
                                    <td className="px-4 py-3">
                                      {cred.compromised ? (
                                        <span className="status-badge status-error text-xs">COMPROMISED</span>
                                      ) : (
                                        <span className="status-badge status-success text-xs">SECURE</span>
                                      )}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>

                        {/* All Usernames */}
                        <div className="mb-6">
                          <div className="label-uppercase text-xs mb-3">ALL USERNAMES FOUND</div>
                          <div className="flex flex-wrap gap-2">
                            {auditResults.detailed_findings.all_usernames.map((username, idx) => (
                              <span key={idx} className="px-3 py-1 bg-[#F4F4F5] border border-[#E4E4E7] font-code text-xs">
                                {username}
                              </span>
                            ))}
                          </div>
                        </div>

                        {/* All Linked Emails */}
                        {auditResults.detailed_findings.all_linked_emails.length > 0 && (
                          <div className="mb-6">
                            <div className="label-uppercase text-xs mb-3">LINKED & RECOVERY EMAILS</div>
                            <div className="space-y-2">
                              {auditResults.detailed_findings.all_linked_emails.map((email, idx) => (
                                <div key={idx} className="flex items-center justify-between py-2 px-3 bg-[#F4F4F5] border border-[#E4E4E7]">
                                  <span className="font-code text-xs text-[#09090B]">{email}</span>
                                  <button
                                    onClick={() => copyToClipboard(email)}
                                    className="p-1 hover:bg-white transition-colors"
                                  >
                                    <Copy className="w-3 h-3 text-[#71717A]" />
                                  </button>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Domain Analysis */}
                        {auditResults.detailed_findings.domain_analysis && (
                          <div className="border border-[#E4E4E7] p-4">
                            <div className="label-uppercase text-xs mb-3">DOMAIN ANALYSIS</div>
                            <div className="space-y-3 text-sm">
                              <div className="flex justify-between">
                                <span className="text-[#71717A]">Domain:</span>
                                <span className="font-code text-[#09090B]">{auditResults.detailed_findings.domain_analysis.domain}</span>
                              </div>
                              <div>
                                <span className="text-[#71717A] block mb-2">Exposed Emails:</span>
                                <div className="space-y-1">
                                  {auditResults.detailed_findings.domain_analysis.emails_found.map((email, idx) => (
                                    <div key={idx} className="font-code text-xs text-[#09090B] bg-[#F4F4F5] p-2">
                                      {email}
                                    </div>
                                  ))}
                                </div>
                              </div>
                              {auditResults.detailed_findings.domain_analysis.subdomains_found.length > 0 && (
                                <div>
                                  <span className="text-[#71717A] block mb-2">Subdomains Found:</span>
                                  <div className="flex flex-wrap gap-2">
                                    {auditResults.detailed_findings.domain_analysis.subdomains_found.map((sub, idx) => (
                                      <span key={idx} className="px-2 py-1 bg-[#F4F4F5] border border-[#E4E4E7] font-code text-xs">
                                        {sub}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {auditResults.vulnerabilities.length > 0 && (
                    <div className="border border-[#E4E4E7]">
                      <div className="bg-[#F4F4F5] px-6 py-3 border-b border-[#E4E4E7]">
                        <div className="label-uppercase">DETAILED VULNERABILITIES</div>
                      </div>
                      <div className="divide-y divide-[#E4E4E7]">
                        {auditResults.vulnerabilities.map((vuln, idx) => (
                          <div key={idx} className="p-6">
                            <div className="flex items-start justify-between mb-3">
                              <div>
                                <h3 className="font-body font-medium text-[#09090B] text-lg mb-1">{vuln.type}</h3>
                                <p className="text-sm text-[#71717A]">{vuln.description}</p>
                              </div>
                              <span className={`status-badge ${
                                vuln.severity === 'critical' ? 'status-error' :
                                vuln.severity === 'high' ? 'status-warning' :
                                'bg-[#FFCC00] text-[#09090B] border-[#FFCC00]'
                              }`}>
                                {vuln.severity}
                              </span>
                            </div>

                            {/* Affected Accounts */}
                            {vuln.affected_accounts && vuln.affected_accounts.length > 0 && (
                              <div className="mb-3 p-3 bg-[#F4F4F5] border border-[#E4E4E7]">
                                <div className="label-uppercase text-xs mb-2">AFFECTED ACCOUNTS</div>
                                <div className="space-y-1">
                                  {vuln.affected_accounts.map((acc, i) => (
                                    <div key={i} className="font-code text-xs text-[#09090B]">• {acc}</div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Exposed Passwords */}
                            {vuln.exposed_passwords && vuln.exposed_passwords.length > 0 && (
                              <div className="mb-3 p-3 bg-[#FFE6E6] border-2 border-[#FF3333]">
                                <div className="label-uppercase text-xs text-[#FF3333] mb-2">EXPOSED PASSWORDS</div>
                                <div className="space-y-2">
                                  {vuln.exposed_passwords.map((pwd, i) => (
                                    <div key={i} className="bg-white p-2 border border-[#FF3333]">
                                      <div className="text-xs text-[#71717A] mb-1">{pwd.account}</div>
                                      <div className="flex items-center gap-2">
                                        <span className="font-code text-sm font-bold text-[#FF3333]">{pwd.password}</span>
                                        <button
                                          onClick={() => copyToClipboard(pwd.password)}
                                          className="p-1 hover:bg-[#F4F4F5] transition-colors"
                                        >
                                          {copied ? <Check className="w-3 h-3 text-[#00CC66]" /> : <Copy className="w-3 h-3 text-[#FF3333]" />}
                                        </button>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Remediation Steps */}
                            {vuln.remediation_steps && (
                              <div className="p-3 bg-[#E6F7EE] border border-[#00CC66]">
                                <div className="label-uppercase text-xs text-[#00CC66] mb-2">HOW TO FIX</div>
                                <ul className="space-y-1">
                                  {vuln.remediation_steps.map((step, i) => (
                                    <li key={i} className="text-sm text-[#09090B] flex items-start gap-2">
                                      <span className="text-[#00CC66]">✓</span>
                                      <span>{step}</span>
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Premium Services */}
            <div className="bg-white border border-[#E4E4E7] p-8">
              <div className="label-uppercase mb-6">PREMIUM SECURITY SERVICES</div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {auditResults && auditResults.premium_features.map((service, idx) => (
                  <div
                    key={idx}
                    className="border-2 border-[#E4E4E7] p-6 hover:border-[#0055FF] transition-colors cursor-pointer"
                    onClick={() => setSelectedService(service)}
                  >
                    <div className="flex items-start justify-between mb-4">
                      <h3 className="font-heading font-black text-xl text-[#09090B]">{service.service}</h3>
                      <div className="text-right">
                        <div className="font-heading font-black text-2xl text-[#0055FF]">
                          ${service.price}
                        </div>
                        <div className="text-xs text-[#71717A]">{service.duration}</div>
                      </div>
                    </div>
                    <p className="text-sm text-[#71717A] mb-4">{service.description}</p>
                    <div className="space-y-2">
                      {service.deliverables.map((item, i) => (
                        <div key={i} className="flex items-center gap-2 text-sm">
                          <Check className="w-4 h-4 text-[#00CC66]" />
                          <span className="text-[#09090B]">{item}</span>
                        </div>
                      ))}
                    </div>
                    <button
                      data-testid={`purchase-${idx}`}
                      className="w-full mt-4 bg-[#0055FF] text-white py-3 font-body font-medium hover:bg-[#0044DD] transition-colors"
                      onClick={(e) => {
                        e.stopPropagation();
                        toast.success(`Payment integration would process $${service.price} for ${service.service}`);
                      }}
                    >
                      PURCHASE NOW
                    </button>
                  </div>
                ))}
              </div>

              {!auditResults && (
                <div className="text-center py-12 text-[#71717A] font-body">
                  Run a security audit above to view personalized service recommendations
                </div>
              )}
            </div>
          </div>
        )}

        {/* Social Media Search */}
        {activeTab === 'social' && (
          <div className="max-w-7xl mx-auto">
            <div className="bg-white border border-[#E4E4E7] p-8 mb-6">
              <div className="label-uppercase mb-4">SOCIAL MEDIA ACCOUNT DISCOVERY</div>
              <p className="text-[#71717A] font-body mb-6">
                Search all major social media platforms to find accounts, check for compromises, and view exposed passwords.
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-12 gap-4 mb-6">
                <div className="md:col-span-3">
                  <select
                    data-testid="social-search-type"
                    value={socialSearchType}
                    onChange={(e) => setSocialSearchType(e.target.value)}
                    className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-body focus:outline-none focus:border-[#0055FF]"
                  >
                    <option value="email">Email Address</option>
                    <option value="username">Username</option>
                  </select>
                </div>
                <div className="md:col-span-7">
                  <input
                    data-testid="social-query-input"
                    type="text"
                    value={socialQuery}
                    onChange={(e) => setSocialQuery(e.target.value)}
                    placeholder={socialSearchType === 'email' ? 'user@example.com' : 'username'}
                    className="w-full px-4 py-3 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-body focus:outline-none focus:border-[#0055FF]"
                  />
                </div>
                <div className="md:col-span-2">
                  <button
                    data-testid="search-social-btn"
                    onClick={searchSocialMedia}
                    disabled={loading}
                    className="w-full btn-primary h-full flex items-center justify-center gap-2"
                  >
                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Globe className="w-5 h-5" />}
                    SEARCH
                  </button>
                </div>
              </div>

              <div className="p-4 bg-[#FFF5E6] border border-[#FFCC00]">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-5 h-5 text-[#FFCC00] flex-shrink-0 mt-0.5" />
                  <div className="text-sm text-[#09090B] font-body">
                    <strong>Ethical Use:</strong> Only search for accounts you own or have authorization to investigate.
                    All searches are logged and monitored for compliance.
                  </div>
                </div>
              </div>
            </div>

            {socialResults && (
              <div className="space-y-6">
                {/* Summary */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-[#E4E4E7]">
                  <div className="bg-white p-6">
                    <div className="label-uppercase mb-2">ACCOUNTS FOUND</div>
                    <div className="font-heading font-black text-4xl text-[#0055FF]">
                      {socialResults.total_accounts}
                    </div>
                  </div>
                  <div className="bg-white p-6">
                    <div className="label-uppercase mb-2">COMPROMISED</div>
                    <div className="font-heading font-black text-4xl text-[#FF3333]">
                      {socialResults.compromised_count}
                    </div>
                  </div>
                  <div className="bg-white p-6">
                    <div className="label-uppercase mb-2">PLATFORMS</div>
                    <div className="font-body text-sm text-[#71717A] mt-2">
                      {socialResults.platforms_found.join(', ')}
                    </div>
                  </div>
                </div>

                {/* Accounts */}
                <div className="bg-white border border-[#E4E4E7]">
                  <div className="bg-[#F4F4F5] px-6 py-3 border-b border-[#E4E4E7]">
                    <div className="label-uppercase">DISCOVERED ACCOUNTS</div>
                  </div>
                  <div className="divide-y divide-[#E4E4E7]">
                    {socialResults.accounts.map((account, idx) => (
                      <div key={idx} className="p-6">
                        <div className="flex items-start justify-between mb-4">
                          <div>
                            <div className="flex items-center gap-3 mb-2">
                              <h3 className="font-heading font-black text-xl text-[#09090B]">
                                {account.name}
                              </h3>
                              {account.compromised && (
                                <span className="status-badge status-error">COMPROMISED</span>
                              )}
                              {!account.has_2fa && (
                                <span className="status-badge status-warning">NO 2FA</span>
                              )}
                            </div>
                            <div className="flex items-center gap-4 text-sm text-[#71717A]">
                              <span className="font-code">{account.username}</span>
                              <span>•</span>
                              <span>{account.followers} followers</span>
                              <span>•</span>
                              <span>Created: {account.created_date}</span>
                            </div>
                          </div>
                          <a
                            href={account.profile_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn-outline py-2 px-4 text-sm"
                          >
                            VIEW PROFILE
                          </a>
                        </div>

                        {account.compromised && (
                          <div className="border border-[#FF3333] bg-[#FFE6E6] p-4 mb-3">
                            <div className="flex items-start gap-3 mb-3">
                              <Lock className="w-5 h-5 text-[#FF3333] flex-shrink-0 mt-0.5" />
                              <div>
                                <div className="font-body font-medium text-[#FF3333] mb-1">
                                  DATA BREACH DETECTED - {account.breach_date}
                                </div>
                                <div className="text-sm text-[#09090B]">
                                  <strong>Exposed:</strong> {account.exposed_data.join(', ')}
                                </div>
                              </div>
                            </div>

                            {account.password_found && (
                              <div className="mt-3 pt-3 border-t border-[#FF3333]">
                                <div className="label-uppercase text-[#FF3333] mb-2 text-xs">
                                  COMPROMISED PASSWORD
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                  <div>
                                    <div className="text-xs text-[#71717A] mb-1">Hash:</div>
                                    <div className="font-code text-xs bg-white border border-[#FF3333] p-2 break-all">
                                      {account.password_hash}
                                    </div>
                                  </div>
                                  <div>
                                    <div className="text-xs text-[#71717A] mb-1">Plaintext:</div>
                                    <div className="flex items-center gap-2">
                                      <div className="font-code text-sm font-bold text-[#FF3333] bg-white border border-[#FF3333] p-2 flex-1">
                                        {account.password_plaintext}
                                      </div>
                                      <button
                                        onClick={() => copyToClipboard(account.password_plaintext)}
                                        className="p-2 hover:bg-white border border-[#FF3333] transition-colors"
                                      >
                                        {copied ? <Check className="w-4 h-4 text-[#00CC66]" /> : <Copy className="w-4 h-4 text-[#FF3333]" />}
                                      </button>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        )}

                        {!account.compromised && (
                          <div className="border border-[#00CC66] bg-[#E6F7EE] p-3 flex items-center gap-2">
                            <Check className="w-5 h-5 text-[#00CC66]" />
                            <span className="text-sm text-[#09090B]">
                              No breaches detected • Account appears secure
                            </span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Remediation Services */}
                {socialResults.compromised_count > 0 && (
                  <div className="bg-white border border-[#E4E4E7] p-8">
                    <div className="label-uppercase mb-6">PROFESSIONAL REMEDIATION SERVICES</div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      {socialResults.remediation_services.map((service, idx) => (
                        <div
                          key={idx}
                          className={`border-2 p-6 relative ${
                            service.popular ? 'border-[#0055FF] bg-[#E6F0FF]' :
                            service.urgent ? 'border-[#FF3333] bg-[#FFE6E6]' :
                            'border-[#E4E4E7] bg-white'
                          }`}
                        >
                          {service.popular && (
                            <div className="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-[#0055FF] text-white px-4 py-1 text-xs font-bold">
                              MOST POPULAR
                            </div>
                          )}
                          {service.urgent && (
                            <div className="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-[#FF3333] text-white px-4 py-1 text-xs font-bold">
                              URGENT
                            </div>
                          )}
                          
                          <div className="text-center mb-4 mt-2">
                            <div className="font-heading font-black text-3xl mb-1 text-[#0055FF]">
                              ${service.price}
                            </div>
                            <div className="text-xs text-[#71717A]">{service.duration}</div>
                          </div>
                          
                          <h3 className="font-heading font-black text-lg text-[#09090B] mb-3 text-center">
                            {service.service}
                          </h3>
                          
                          <p className="text-sm text-[#71717A] mb-4 text-center">
                            {service.description}
                          </p>
                          
                          <div className="space-y-2 mb-4">
                            {service.deliverables.map((item, i) => (
                              <div key={i} className="flex items-start gap-2 text-sm">
                                <Check className="w-4 h-4 text-[#00CC66] flex-shrink-0 mt-0.5" />
                                <span className="text-[#09090B]">{item}</span>
                              </div>
                            ))}
                          </div>

                          {service.savings && (
                            <div className="text-xs text-[#00CC66] font-medium mb-3 text-center">
                              {service.savings}
                            </div>
                          )}
                          
                          <button
                            data-testid={`purchase-social-${idx}`}
                            className={`w-full py-3 font-body font-medium transition-colors ${
                              service.popular ? 'bg-[#0055FF] text-white hover:bg-[#0044DD]' :
                              service.urgent ? 'bg-[#FF3333] text-white hover:bg-[#DD2222]' :
                              'bg-[#09090B] text-white hover:bg-[#18181B]'
                            }`}
                            onClick={() => {
                              toast.success(`Payment integration would process $${service.price} for ${service.service}`);
                            }}
                          >
                            {service.urgent ? 'GET HELP NOW' : 'PURCHASE NOW'}
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Free Recommendations */}
                {socialResults.security_recommendations && (
                  <div className="bg-white border border-[#E4E4E7] p-8">
                    <div className="label-uppercase mb-4">FREE SECURITY RECOMMENDATIONS</div>
                    <ul className="space-y-3">
                      {socialResults.security_recommendations.map((rec, idx) => (
                        <li key={idx} className="flex items-start gap-3 font-body text-[#09090B]">
                          <span className="flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center bg-[#0055FF] text-white text-xs font-bold">
                            {idx + 1}
                          </span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {!socialResults && (
              <div className="bg-white border border-[#E4E4E7] p-12 text-center text-[#71717A] font-body">
                Enter an email address or username above to search for social media accounts
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
