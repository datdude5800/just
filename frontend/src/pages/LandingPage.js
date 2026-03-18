import { useNavigate } from 'react-router-dom';
import { Shield, Lock, AlertTriangle, Code } from 'lucide-react';

const LandingPage = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-white">
      {/* Navigation */}
      <nav className="border-b border-[#E4E4E7] bg-white/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-[#0055FF]" />
            <h1 className="font-heading font-black text-2xl tracking-tightest text-[#09090B]">SECCHECK</h1>
          </div>
          <button
            data-testid="launch-dashboard-btn"
            onClick={() => navigate('/dashboard')}
            className="btn-primary"
          >
            LAUNCH DASHBOARD
          </button>
        </div>
      </nav>

      {/* Hero Section - Tetris Grid */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-0 border-b border-[#E4E4E7]">
        {/* Main Hero */}
        <div className="md:col-span-8 border-r border-[#E4E4E7] p-16 md:p-24 bg-white">
          <div className="max-w-3xl">
            <div className="label-uppercase mb-6">ETHICAL SECURITY TESTING</div>
            <h1 className="font-heading font-black text-5xl md:text-6xl lg:text-7xl tracking-tightest text-[#09090B] mb-8 leading-tight">
              Professional
              <br />
              Penetration Testing
              <br />
              <span className="text-[#0055FF]">& Hash Analysis</span>
            </h1>
            <p className="text-lg text-[#71717A] font-body mb-12 leading-relaxed">
              Comprehensive security auditing suite for ethical hackers and developers.
              Test your applications, decode cryptographic hashes, and identify vulnerabilities
              before malicious actors do.
            </p>
            <div className="flex gap-4">
              <button
                data-testid="get-started-btn"
                onClick={() => navigate('/dashboard')}
                className="btn-primary text-lg px-8 py-4"
              >
                GET STARTED
              </button>
              <button
                data-testid="view-features-btn"
                className="btn-outline text-lg px-8 py-4"
              >
                VIEW FEATURES
              </button>
            </div>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="md:col-span-4 grid grid-cols-1 gap-0">
          <div className="border-b border-[#E4E4E7] p-12 bg-[#F4F4F5]">
            <div className="font-heading font-black text-5xl text-[#0055FF] mb-3">15+</div>
            <div className="label-uppercase text-[#71717A]">HASH ALGORITHMS</div>
          </div>
          <div className="border-b border-[#E4E4E7] p-12 bg-white">
            <div className="font-heading font-black text-5xl text-[#FF3333] mb-3">10+</div>
            <div className="label-uppercase text-[#71717A]">SECURITY TESTS</div>
          </div>
          <div className="p-12 bg-[#F4F4F5]">
            <div className="font-heading font-black text-5xl text-[#09090B] mb-3">100%</div>
            <div className="label-uppercase text-[#71717A]">ETHICAL USE</div>
          </div>
        </div>
      </div>

      {/* Disclaimer Section */}
      <div className="border-b border-[#E4E4E7] bg-[#FF3333] px-6 py-8">
        <div className="max-w-7xl mx-auto flex items-start gap-4">
          <AlertTriangle className="w-6 h-6 text-white flex-shrink-0 mt-1" />
          <div>
            <h3 className="font-heading font-black text-xl text-white mb-2">ETHICAL USE ONLY</h3>
            <p className="text-white/90 font-body">
              This tool is designed for authorized security testing only. Always obtain explicit written
              permission before testing any system you do not own. Unauthorized access to computer systems
              is illegal and punishable by law.
            </p>
          </div>
        </div>
      </div>

      {/* Features Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-0 border-b border-[#E4E4E7]">
        <div className="border-r border-[#E4E4E7] p-12 bg-white">
          <div className="w-12 h-12 border-2 border-[#0055FF] flex items-center justify-center mb-6">
            <Shield className="w-6 h-6 text-[#0055FF]" />
          </div>
          <h3 className="font-heading font-black text-2xl text-[#09090B] mb-4">Penetration Testing</h3>
          <p className="text-[#71717A] font-body mb-6">
            Port scanning, SSL/TLS validation, security header analysis, XSS detection,
            and SQL injection testing.
          </p>
          <div className="label-uppercase text-[#0055FF]">COMPREHENSIVE SUITE</div>
        </div>

        <div className="border-r border-[#E4E4E7] p-12 bg-[#F4F4F5]">
          <div className="w-12 h-12 border-2 border-[#FF3333] flex items-center justify-center mb-6">
            <Lock className="w-6 h-6 text-[#FF3333]" />
          </div>
          <h3 className="font-heading font-black text-2xl text-[#09090B] mb-4">Hash Decoder</h3>
          <p className="text-[#71717A] font-body mb-6">
            Identify and analyze cryptographic hashes. Supports MD5, SHA family, bcrypt,
            BLAKE2, and all major algorithms.
          </p>
          <div className="label-uppercase text-[#FF3333]">ALL HASH TYPES</div>
        </div>

        <div className="p-12 bg-white">
          <div className="w-12 h-12 border-2 border-[#00CC66] flex items-center justify-center mb-6">
            <Code className="w-6 h-6 text-[#00CC66]" />
          </div>
          <h3 className="font-heading font-black text-2xl text-[#09090B] mb-4">API Security</h3>
          <p className="text-[#71717A] font-body mb-6">
            Test REST API endpoints for security vulnerabilities, analyze response headers,
            and identify misconfigurations.
          </p>
          <div className="label-uppercase text-[#00CC66]">REST API TESTING</div>
        </div>
      </div>

      {/* Visual Section */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-0">
        <div className="border-r border-[#E4E4E7] p-16 bg-white">
          <div className="label-uppercase mb-4">SECURITY FIRST</div>
          <h2 className="font-heading font-black text-4xl text-[#09090B] mb-6 tracking-tightest">
            Built for
            <br />
            Security Professionals
          </h2>
          <p className="text-[#71717A] font-body text-lg mb-8">
            Clinical precision meets comprehensive security testing. Every feature designed
            with professional penetration testers in mind.
          </p>
          <button
            data-testid="start-testing-btn"
            onClick={() => navigate('/dashboard')}
            className="btn-primary px-8 py-3"
          >
            START TESTING
          </button>
        </div>
        <div className="bg-[#F4F4F5] p-16 flex items-center justify-center">
          <img
            src="https://images.unsplash.com/photo-1623305464543-b224da93e482?crop=entropy&cs=srgb&fm=jpg&q=85"
            alt="Abstract security layers"
            className="w-full h-96 object-cover border border-[#E4E4E7]"
          />
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-[#E4E4E7] bg-[#09090B] text-white p-12">
        <div className="max-w-7xl mx-auto text-center">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-6 h-6" />
            <h3 className="font-heading font-black text-xl">SECCHECK</h3>
          </div>
          <p className="text-white/60 font-body">
            Ethical Security Testing Platform • 2026
          </p>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;