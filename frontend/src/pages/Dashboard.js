import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Shield, Hash, Globe, Play, Loader2, ChevronDown, ChevronUp, Copy, Check } from 'lucide-react';
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
          <div className="label-uppercase text-[#71717A]">SECURITY DASHBOARD</div>
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
      </div>
    </div>
  );
};

export default Dashboard;
