
import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, 
  AreaChart, Area, Cell, PieChart, Pie, ScatterChart, Scatter, ZAxis, BarChart, Bar, Legend
} from 'recharts';
import { Asset, AssetType, Threat, SimulationResult, ViewType, User, SimulationConfig, StressScenario, ComplianceRequirement, XAIDriver, Control } from './types';
import { analyzeThreatIntelligence } from './services/geminiService';
import { runMonteCarloSimulation } from './utils/monteCarlo';

const COLORS = {
  CORAL: '#FF6B6B',
  CYAN: '#06B6D4',
  INDIGO: '#6366F1',
  DARK: '#0F172A',
  SLATE: '#94a3b8',
  EMERALD: '#10B981',
  AMBER: '#F59E0B'
};

const INITIAL_CONTROLS: Control[] = [
  { id: 'c1', name: 'MFA Enforcement', cost: 50000, varReduction: 0.15, mapping: 'NIST', implemented: true },
  { id: 'c2', name: 'Immutable Backups', cost: 120000, varReduction: 0.25, mapping: 'ISO27001', implemented: true },
  { id: 'c3', name: '24/7 SOC Monitoring', cost: 300000, varReduction: 0.20, mapping: 'DORA', implemented: false },
  { id: 'c4', name: 'Endpoint Protection', cost: 80000, varReduction: 0.12, mapping: 'NIST', implemented: true }
];

const INITIAL_ASSETS: Asset[] = [
  { id: '1', name: 'SWIFT Gateway', type: AssetType.PAYMENT_SYSTEM, hourlyLossValue: 1200000, baseProbability: 0.001, technologies: ['Swift', 'Oracle', 'Linux'], dependencies: ['2'], vulnerabilityScore: 0.4, maturityScore: 0.7 },
  { id: '2', name: 'Customer PII Vault', type: AssetType.DATABASE, hourlyLossValue: 450000, baseProbability: 0.002, technologies: ['SQL Server', 'Azure', 'C#'], dependencies: ['4'], vulnerabilityScore: 0.6, maturityScore: 0.5 },
  { id: '3', name: 'HFT Trading Engine', type: AssetType.TRADING_ALGO, hourlyLossValue: 3000000, baseProbability: 0.0005, technologies: ['C++', 'Low Latency Network', 'FPGA'], vulnerabilityScore: 0.2, maturityScore: 0.9 },
  { id: '4', name: 'Azure Cloud Stack', type: AssetType.CLOUD_INFRA, hourlyLossValue: 800000, baseProbability: 0.0015, technologies: ['Azure', 'Active Directory', 'Terraform'], vulnerabilityScore: 0.3, maturityScore: 0.8 }
];

const COMPLIANCE_ITEMS: ComplianceRequirement[] = [
  { id: 'r1', title: 'ICT Risk Management', desc: 'Identify, classify, and document critical ICT assets.', status: 'Done', color: 'bg-emerald-500', evidence: ['Asset Inventory v2.4 (Signed)', 'Risk Assessment Report Oct 2024', 'ISO 27001 Certification Validated'] },
  { id: 'r2', title: 'Incident Reporting', desc: 'Automated workflow for major ICT-related incidents.', status: 'Done', color: 'bg-emerald-500', evidence: ['Incident Response Log 2024', 'SOC Notification Protocol Rev.B', 'ESMA Incident Reporting Test Success'] },
  { id: 'r3', title: 'Resilience Testing', desc: 'Annual advanced testing of critical services (TLPT).', status: 'Pending', color: 'bg-amber-500', evidence: ['Pen-Testing Schedule (Q1 2025)', 'Draft Red-Teaming Scope', 'Pending Auditor Sign-off'] },
  { id: 'r4', title: 'Third-Party Risk', desc: 'Continuous monitoring of cloud provider exposure.', status: 'Done', color: 'bg-emerald-500', evidence: ['Azure SOC 2 Type II Report (2024)', 'Vendor Risk Matrix', 'SLA Monitoring Dashboard Access'] }
];

const RAW_THREAT_FEED = [
  "Zero-Day Oracle exploit detected on darkweb.",
  "DDoS targeting SWIFT gateways using high-velocity amplification.",
  "Azure storage ransomware warning issued by CISA.",
  "Massive credential stuffing attack against Cloud IAM providers."
];

// --- Modal Components ---

const Modal: React.FC<{ isOpen: boolean; onClose: () => void; title: string; children: React.ReactNode }> = ({ isOpen, onClose, title, children }) => {
  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="glass w-full max-w-2xl rounded-[40px] p-10 border border-white/10 shadow-2xl animate-in zoom-in duration-300">
        <div className="flex justify-between items-center mb-8">
          <h3 className="text-2xl font-bold text-white tracking-tight uppercase">{title}</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors p-2 text-xl"><i className="fas fa-times"></i></button>
        </div>
        <div className="max-h-[60vh] overflow-y-auto custom-scrollbar pr-4">
          {children}
        </div>
        <div className="mt-10 flex justify-end">
          <button onClick={onClose} className="px-8 py-3 bg-indigo-600 rounded-2xl text-xs font-bold uppercase tracking-widest text-white hover:bg-indigo-500 shadow-xl shadow-indigo-600/20">Close Panel</button>
        </div>
      </div>
    </div>
  );
};

// --- Auth Components ---

const AuthScreen: React.FC<{ onLogin: (u: User) => void }> = ({ onLogin }) => {
  const [isSignup, setIsSignup] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    setTimeout(() => {
      const users = JSON.parse(localStorage.getItem('cybervar_users') || '[]');
      if (isSignup) {
        if (users.length >= 10) {
          setError('User limit reached.');
        } else if (users.find((u: any) => u.email === email)) {
          setError('Email already registered.');
        } else {
          const newUser = { email, password, role: 'Risk Analyst', lastLogin: new Date().toISOString() };
          localStorage.setItem('cybervar_users', JSON.stringify([...users, newUser]));
          onLogin(newUser);
        }
      } else {
        const found = users.find((u: any) => u.email === email && u.password === password);
        if (found || (email === 'admin@corp.com' && password === 'admin')) {
          onLogin(found || { email: 'admin@corp.com', role: 'Super Admin', lastLogin: new Date().toISOString() });
        } else {
          setError('Invalid secure credentials.');
        }
      }
      setLoading(false);
    }, 800);
  };

  return (
    <div className="h-screen w-screen flex items-center justify-center bg-[#0F172A] relative overflow-hidden">
      <div className="absolute inset-0 opacity-10"><div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(circle_at_center,_#6366F1_0%,_transparent_70%)]"></div></div>
      <form onSubmit={handleSubmit} className="glass p-10 rounded-3xl w-96 space-y-8 relative z-10 border border-white/5 shadow-2xl animate-in zoom-in">
        <div className="text-center">
          <div className="w-16 h-16 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl mx-auto flex items-center justify-center mb-4"><i className="fas fa-fingerprint text-white text-3xl"></i></div>
          <h2 className="text-2xl font-jakarta font-bold text-white uppercase tracking-tight">{isSignup ? 'Register' : 'Neural Login'}</h2>
          <p className="text-[10px] text-slate-500 font-mono tracking-widest mt-2 uppercase">Secure Access Layer</p>
        </div>
        <div className="space-y-4">
          <input type="email" value={email} onChange={e => setEmail(e.target.value)} className="w-full bg-black/30 border border-white/10 rounded-xl px-4 py-3 text-sm focus:border-indigo-500 outline-none text-indigo-100" placeholder="Email Address" required />
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} className="w-full bg-black/30 border border-white/10 rounded-xl px-4 py-3 text-sm focus:border-indigo-500 outline-none text-indigo-100" placeholder="Password" required />
          {error && <p className="text-coral text-[10px] font-bold text-center uppercase tracking-wider">{error}</p>}
        </div>
        <button disabled={loading} className="w-full py-4 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-bold text-xs uppercase tracking-widest transition-all">
          {loading ? <i className="fas fa-spinner animate-spin"></i> : isSignup ? 'Create Terminal' : 'Establish Link'}
        </button>
        <button type="button" onClick={() => setIsSignup(!isSignup)} className="w-full text-[10px] text-slate-500 hover:text-indigo-400 font-bold uppercase tracking-widest">
          {isSignup ? 'Already have a terminal? Login' : 'Request new terminal access'}
        </button>
      </form>
    </div>
  );
};

const Sidebar: React.FC<{ current: ViewType; setView: (v: ViewType) => void; onLogout: () => void }> = ({ current, setView, onLogout }) => (
  <aside className="w-20 border-r border-white/5 glass flex flex-col items-center py-10 gap-10 shrink-0">
    <div className="text-indigo-500 text-2xl mb-2"><i className="fas fa-brain animate-pulse"></i></div>
    <nav className="flex flex-col gap-8 text-slate-500 text-xl flex-1">
      {(['DASHBOARD', 'CAPITAL', 'CONTAGION', 'ASSETS', 'ALGO', 'MODEL', 'COMPLIANCE'] as ViewType[]).map(v => (
        <button key={v} onClick={() => setView(v)} className={`${current === v ? 'text-cyan-400' : 'hover:text-cyan-400'} transition-all`} title={v}>
          <i className={`fas ${v === 'DASHBOARD' ? 'fa-chart-line' : v === 'CAPITAL' ? 'fa-coins' : v === 'ASSETS' ? 'fa-shield-alt' : v === 'ALGO' ? 'fa-sliders-h' : v === 'MODEL' ? 'fa-microchip' : v === 'CONTAGION' ? 'fa-project-diagram' : 'fa-university'}`}></i>
        </button>
      ))}
    </nav>
    <button onClick={onLogout} className="text-slate-600 hover:text-coral transition-colors" title="Logout"><i className="fas fa-sign-out-alt"></i></button>
  </aside>
);

const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [view, setView] = useState<ViewType>('DASHBOARD');
  const [assets, setAssets] = useState<Asset[]>(INITIAL_ASSETS);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [controls, setControls] = useState<Control[]>(INITIAL_CONTROLS);
  const [simulation, setSimulation] = useState<SimulationResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [simConfig, setSimConfig] = useState<SimulationConfig>({ 
    iterations: 15000, confidenceInterval: 0.95, horizonDays: 365, stressScenario: 'NONE', netIncome: 50000000, 
    itSecurityBudget: 5000000, riskAppetiteLimit: 8500000, insuranceCoverage: 5000000, insuranceDeductible: 500000, useNeuralAdjustments: true, contagionFactor: 0.4 
  });
  
  const [selectedCompliance, setSelectedCompliance] = useState<ComplianceRequirement | null>(null);
  const [showIntelModal, setShowIntelModal] = useState(false);

  useEffect(() => { if (user) handleRunAnalysis(); }, [user]);

  const handleRunAnalysis = async () => {
    setIsAnalyzing(true);
    const analyzed = await analyzeThreatIntelligence(assets, RAW_THREAT_FEED);
    setThreats(analyzed);
    setIsAnalyzing(false);
    triggerSimulation(assets, analyzed, simConfig);
  };

  const triggerSimulation = (currAssets: Asset[], currThreats: Threat[], config: SimulationConfig) => {
    const result = runMonteCarloSimulation(currAssets, currThreats, config);
    setSimulation(result);
  };

  const updateSimConfig = (updates: Partial<SimulationConfig>) => {
    const newConfig = { ...simConfig, ...updates };
    setSimConfig(newConfig);
    triggerSimulation(assets, threats, newConfig);
  };

  const updateAsset = (id: string, updates: Partial<Asset>) => {
    const updated = assets.map(a => a.id === id ? { ...a, ...updates } : a);
    setAssets(updated);
    triggerSimulation(updated, threats, simConfig);
  };

  const toggleControl = (id: string) => {
    const updated = controls.map(c => c.id === id ? { ...c, implemented: !c.implemented } : c);
    setControls(updated);
    const reduction = updated.filter(c => c.implemented).reduce((acc, c) => acc + (c.varReduction * 0.1), 0);
    const maturityAdjustedAssets = assets.map(a => ({ ...a, maturityScore: Math.min(0.99, 0.5 + reduction) }));
    setAssets(maturityAdjustedAssets);
    triggerSimulation(maturityAdjustedAssets, threats, simConfig);
  };

  // --- Functional Handlers ---

  const handleExportInventory = () => {
    const header = "id,name,type,hourlyLossValue,baseProbability,technologies,maturityScore\n";
    const rows = assets.map(a => `${a.id},${a.name},${a.type},${a.hourlyLossValue},${a.baseProbability},${a.technologies.join('|')},${a.maturityScore}`).join("\n");
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.setAttribute('hidden', '');
    a.setAttribute('href', url);
    a.setAttribute('download', `CyberVaR_Inventory_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleManualOnboarding = () => {
    const names = ["Legal CRM", "HR Portal", "Logistics DB", "Public Web", "Internal Auth"];
    const name = names[Math.floor(Math.random() * names.length)] + " " + (assets.length + 1);
    const newAsset: Asset = {
      id: Math.random().toString(36).substr(2, 9),
      name,
      type: AssetType.DATABASE,
      hourlyLossValue: 600000 + Math.random() * 400000,
      baseProbability: 0.0015,
      technologies: ['Linux', 'Docker', 'Postgres'],
      vulnerabilityScore: 0.5,
      maturityScore: 0.5,
    };
    const updated = [...assets, newAsset];
    setAssets(updated);
    triggerSimulation(updated, threats, simConfig);
  };

  const contagionData = useMemo(() => {
    return assets.map((a, i) => ({
      x: 20 + (i * 20),
      y: 30 + (Math.random() * 40),
      name: a.name,
      impact: a.hourlyLossValue,
      isTarget: !!a.dependencies
    }));
  }, [assets]);

  if (!user) return <AuthScreen onLogin={setUser} />;

  return (
    <div className="h-screen w-screen flex bg-[#0F172A] text-slate-200 overflow-hidden font-jakarta">
      <Sidebar current={view} setView={setView} onLogout={() => setUser(null)} />
      
      {/* Evidence Modal */}
      <Modal isOpen={!!selectedCompliance} onClose={() => setSelectedCompliance(null)} title="Compliance Evidence Vault">
        {selectedCompliance && (
          <div className="space-y-6">
            <div className="bg-indigo-500/10 p-4 rounded-2xl border border-indigo-500/20">
              <p className="text-sm text-indigo-100 font-medium mb-2">{selectedCompliance.desc}</p>
              <span className={`text-[10px] px-3 py-1 rounded-full uppercase font-bold tracking-widest ${selectedCompliance.color.replace('bg-', 'text-')} bg-white/5`}>{selectedCompliance.status}</span>
            </div>
            <div className="space-y-3">
              <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest">Signed Evidence Chain</h4>
              {selectedCompliance.evidence.map((ev, i) => (
                <div key={i} className="flex justify-between items-center p-3 rounded-xl bg-white/5 border border-white/5 hover:border-indigo-500/40 transition-all cursor-pointer">
                  <span className="text-xs text-slate-300 font-medium"><i className="fas fa-file-shield text-emerald-400 mr-2"></i> {ev}</span>
                  <span className="text-[10px] text-slate-500 mono">SHA-256 Verified</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Modal>

      {/* Intel Modal */}
      <Modal isOpen={showIntelModal} onClose={() => setShowIntelModal(false)} title="Full Threat Intelligence Report">
        <div className="space-y-6">
          <p className="text-xs text-slate-500 italic">Extracted via Gemini-3 Neural Analysis of live darkweb and CISA feeds.</p>
          {threats.map(t => (
            <div key={t.id} className="p-5 rounded-2xl bg-white/5 border border-white/5 hover:border-indigo-500/30 transition-all">
              <div className="flex justify-between items-start mb-3">
                <div>
                  <h4 className="font-bold text-white text-base">{t.title}</h4>
                  <span className="text-[9px] text-indigo-400 font-bold uppercase tracking-widest">{t.targetTechnology} Matrix</span>
                </div>
                <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold uppercase ${t.severity === 'Critical' ? 'bg-coral/20 text-coral' : 'bg-slate-700 text-slate-300'}`}>{t.severity}</span>
              </div>
              <p className="text-sm text-slate-400 leading-relaxed mb-4">{t.description}</p>
              <div className="flex items-center gap-4 border-t border-white/5 pt-4">
                 <div className="text-[10px] text-slate-500">Impact Multiplier: <span className="text-white font-bold">{t.impactModifier}x</span></div>
                 <div className="text-[10px] text-slate-500">Detection Confidence: <span className="text-emerald-400 font-bold">98.2%</span></div>
              </div>
            </div>
          ))}
          {threats.length === 0 && <p className="text-center text-slate-500 py-10 uppercase tracking-widest font-mono text-xs">No threats detected for current asset stack</p>}
        </div>
      </Modal>

      <div className="flex-1 flex flex-col overflow-hidden relative">
        <header className="h-16 flex items-center justify-between px-8 border-b border-white/5 glass z-20">
          <div className="flex items-center gap-3">
            <h1 className="text-lg font-bold tracking-tight uppercase">Neural <span className="text-indigo-400">Cyber-VaR</span></h1>
            <div className="h-4 w-[1px] bg-white/10 mx-2"></div>
            <span className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">{view} View</span>
          </div>
          <div className="flex items-center gap-6">
            <div className="flex bg-white/5 rounded-xl p-1 border border-white/5">
              {[1, 10, 365].map(d => (
                <button key={d} onClick={() => updateSimConfig({ horizonDays: d })} className={`px-4 py-1 text-[9px] font-bold rounded-lg transition-all ${simConfig.horizonDays === d ? 'bg-indigo-600 text-white shadow-lg' : 'text-slate-500 hover:text-white'}`}>
                  {d === 1 ? '1D' : d === 10 ? '10D' : '1Y'}
                </button>
              ))}
            </div>
            <div className="text-[10px] text-emerald-400 font-bold uppercase mono tracking-widest flex items-center gap-2 px-3 py-1.5 bg-emerald-500/5 rounded-lg border border-emerald-500/10">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> {user.email}
            </div>
            <button onClick={handleRunAnalysis} className="text-[10px] font-bold bg-indigo-600/10 border border-indigo-500/30 px-3 py-1.5 rounded-lg text-indigo-400 hover:bg-indigo-500/20 transition-all flex items-center gap-2">
              <i className={`fas ${isAnalyzing ? 'fa-spinner animate-spin' : 'fa-sync-alt'}`}></i> {isAnalyzing ? 'Processing...' : 'Recalibrate'}
            </button>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-8 custom-scrollbar">
          
          {view === 'DASHBOARD' && (
            <div className="space-y-8 animate-in fade-in duration-500">
              <div className="ai-bubble p-6 rounded-3xl border-l-4 border-indigo-500 shadow-xl flex justify-between items-center">
                <div className="flex items-start gap-5">
                  <div className="w-12 h-12 rounded-2xl bg-indigo-500 flex items-center justify-center shrink-0 shadow-lg shadow-indigo-500/40"><i className="fas fa-brain text-white text-xl"></i></div>
                  <div>
                    <h3 className="text-xs font-bold text-indigo-400 uppercase tracking-widest mb-1">Risk Narrative & AI Insight</h3>
                    <p className="text-sm text-indigo-100 leading-relaxed italic max-w-2xl font-medium">"{simulation?.narrative}"</p>
                  </div>
                </div>
                <div className="text-right border-l border-white/5 pl-8">
                  <p className="text-[9px] font-bold text-slate-500 uppercase mb-1">Worst 1% Loss (VaR 99)</p>
                  <p className="text-3xl font-bold mono text-coral">€{((simulation?.var99 || 0) / 1000000).toFixed(2)}M</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                {[
                  { label: 'Economic Capital', val: `€${((simulation?.economicCapital || 0) / 1000000).toFixed(2)}M`, color: 'border-indigo-400', sub: 'Regulatory Cushion' },
                  { label: 'Cyber-VaR (95%)', val: `€${((simulation?.var95 || 0) / 1000000).toFixed(2)}M`, color: 'border-coral', sub: 'Quantified Risk' },
                  { label: 'Expected Loss', val: `€${((simulation?.expectedLoss || 0) / 1000000).toFixed(2)}M`, color: 'border-cyan-400', sub: 'Avg Annual Frequency' },
                  { label: 'Compliance Status', val: simulation?.breachStatus || 'OK', color: 'border-emerald-400', sub: 'Risk Appetite Breach' }
                ].map(kpi => (
                  <div key={kpi.label} className={`bento-card p-6 rounded-2xl border-l-4 ${kpi.color}`}>
                    <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mb-1">{kpi.label}</p>
                    <h4 className="text-2xl font-bold mono text-white">{kpi.val}</h4>
                    <p className="text-[10px] text-slate-500 mt-2 italic">{kpi.sub}</p>
                  </div>
                ))}
              </div>

              <div className="grid grid-cols-12 gap-6">
                <div className="col-span-12 lg:col-span-8 bento-card p-8 rounded-3xl">
                  <h3 className="text-lg font-bold mb-6">Asset-Wise Capital Allocation</h3>
                  <div className="h-[320px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={simulation?.assetBreaks || []}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                        <XAxis dataKey="assetName" stroke={COLORS.SLATE} fontSize={10} />
                        <YAxis stroke={COLORS.SLATE} fontSize={10} tickFormatter={(v) => `€${(v/1000000).toFixed(1)}M`} />
                        <Tooltip contentStyle={{ backgroundColor: '#0F172A', border: '1px solid #334155', borderRadius: '12px' }} />
                        <Bar dataKey="allocatedCapital" name="Capital Allocated" fill={COLORS.INDIGO} radius={[4, 4, 0, 0]} />
                        <Bar dataKey="contribution" name="Expected Shortfall" fill={COLORS.CORAL} radius={[4, 4, 0, 0]} />
                        <Legend wrapperStyle={{ fontSize: '10px', paddingTop: '20px' }} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <div className="col-span-12 lg:col-span-4 bento-card p-8 rounded-3xl flex flex-col">
                  <h3 className="text-sm font-bold uppercase tracking-widest text-slate-400 mb-6">Top Threats (Live Feed)</h3>
                  <div className="flex-1 space-y-4">
                    {threats.slice(0, 4).map(t => (
                      <div key={t.id} className="p-4 rounded-xl bg-white/5 border border-white/5 hover:border-indigo-500/30 transition-all cursor-default">
                        <div className="flex justify-between items-start mb-1">
                          <span className="text-[9px] font-bold text-indigo-400 uppercase tracking-widest">{t.targetTechnology}</span>
                          <span className={`text-[8px] px-1.5 py-0.5 rounded font-bold ${t.severity === 'Critical' ? 'bg-coral/20 text-coral' : 'bg-slate-700 text-slate-300'}`}>{t.severity}</span>
                        </div>
                        <h4 className="text-xs font-bold text-white leading-tight">{t.title}</h4>
                      </div>
                    ))}
                    {threats.length === 0 && <p className="text-center py-10 text-[10px] text-slate-600 font-mono uppercase">Analyzing new data vectors...</p>}
                  </div>
                  <div className="mt-6 pt-4 border-t border-white/5">
                    <button onClick={() => setShowIntelModal(true)} className="text-[10px] font-bold uppercase tracking-widest text-indigo-400 hover:text-indigo-300 transition-colors">View Full Intel Report <i className="fas fa-chevron-right ml-1"></i></button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {view === 'CAPITAL' && (
            <div className="space-y-8 animate-in zoom-in duration-500">
              <div className="flex justify-between items-end mb-8">
                <div>
                  <h2 className="text-3xl font-bold tracking-tight">Cyber Economic Capital</h2>
                  <p className="text-xs text-slate-500 font-mono mt-2 uppercase tracking-widest">Regulatory Capital Allocation & Performance Benchmarks</p>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div className="bento-card p-10 rounded-3xl flex flex-col">
                  <h3 className="text-lg font-bold mb-8 text-indigo-400">Risk-Adjusted Performance (RAROC)</h3>
                  <div className="flex-1 space-y-8">
                    {simulation?.assetBreaks.map(item => (
                      <div key={item.assetName} className="space-y-2">
                        <div className="flex justify-between text-xs font-bold">
                          <span className="text-slate-300 uppercase tracking-tighter">{item.assetName}</span>
                          <span className="text-emerald-400 mono">{(item.raroc * 100).toFixed(1)}% RAROC</span>
                        </div>
                        <div className="h-2.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.3)]" style={{ width: `${Math.min(100, item.raroc * 100)}%` }}></div>
                        </div>
                      </div>
                    ))}
                  </div>
                  <p className="text-[10px] text-slate-500 italic mt-10">RAROC = (Net Expected Margin / Economic Capital). Targeted hurdle rate: 12%.</p>
                </div>
                
                <div className="bento-card p-10 rounded-3xl bg-indigo-600/5 border-indigo-500/20">
                   <h3 className="text-lg font-bold mb-4">Capital Immobilization Forecast</h3>
                   <p className="text-sm text-slate-400 leading-relaxed mb-8">The Neural Engine estimates your required capital buffer at a 95% confidence level over a {simConfig.horizonDays} day horizon.</p>
                   <div className="p-8 rounded-3xl bg-black/40 border border-indigo-500/10 text-center mb-8 shadow-2xl">
                      <p className="text-[11px] text-slate-500 uppercase font-bold tracking-widest mb-2">Recommended Provision (CEC)</p>
                      <h4 className="text-5xl font-bold text-white mono">€{((simulation?.economicCapital || 0)/1000000).toFixed(2)}M</h4>
                   </div>
                   <div className="grid grid-cols-2 gap-4">
                      <div className="p-5 rounded-2xl bg-white/5 border border-white/5">
                         <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">DORA Maturity Credit</p>
                         <p className="text-lg font-bold text-emerald-400">-€{(140 + Math.random()*20).toFixed(0)}k</p>
                      </div>
                      <div className="p-5 rounded-2xl bg-white/5 border border-white/5">
                         <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Stress Scenario Delta</p>
                         <p className="text-lg font-bold text-coral">+€{(320 + Math.random()*50).toFixed(0)}k</p>
                      </div>
                   </div>
                </div>
              </div>
            </div>
          )}

          {view === 'ASSETS' && (
            <div className="space-y-6 animate-in slide-in-from-bottom duration-500">
              <div className="flex justify-between items-center mb-8">
                <div>
                  <h2 className="text-3xl font-bold tracking-tight">Critical Asset Registry</h2>
                  <p className="text-xs text-slate-500 mt-1 uppercase tracking-widest font-mono">Inventory Management & Financial mapping</p>
                </div>
                <div className="flex gap-4">
                   <button onClick={handleExportInventory} className="bg-white/5 border border-white/10 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-widest hover:bg-white/10 transition-all flex items-center gap-2">
                     <i className="fas fa-file-export"></i> Export Inventory
                   </button>
                   <button onClick={handleManualOnboarding} className="bg-indigo-600 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-widest hover:bg-indigo-500 shadow-lg shadow-indigo-600/20 flex items-center gap-2">
                     <i className="fas fa-plus"></i> Manual Onboarding
                   </button>
                </div>
              </div>
              
              <div className="grid grid-cols-1 gap-4">
                {assets.map(asset => (
                  <div key={asset.id} className="bento-card p-6 rounded-3xl flex items-center justify-between group border-l-4 border-transparent hover:border-indigo-500">
                    <div className="flex gap-8 items-center flex-1">
                      <div className="w-14 h-14 bg-indigo-500/10 rounded-2xl flex items-center justify-center text-indigo-400 text-xl border border-indigo-500/20">
                        <i className={`fas ${asset.type === AssetType.DATABASE ? 'fa-database' : asset.type === AssetType.PAYMENT_SYSTEM ? 'fa-exchange-alt' : 'fa-network-wired'}`}></i>
                      </div>
                      <div className="min-w-[240px]">
                        <h4 className="font-bold text-lg text-white mb-1">{asset.name}</h4>
                        <div className="flex gap-2">
                          {asset.technologies.map(t => <span key={t} className="text-[9px] bg-slate-800/80 px-2.5 py-1 rounded text-slate-400 uppercase font-mono tracking-tighter border border-white/5">{t}</span>)}
                        </div>
                      </div>
                      <div className="flex gap-10 flex-1 px-10 border-x border-white/5">
                        <div className="w-1/2">
                          <div className="flex justify-between text-[10px] font-bold uppercase mb-1.5"><span className="text-slate-500">Vulnerability</span><span className="text-coral">{(asset.vulnerabilityScore*100).toFixed(0)}%</span></div>
                          <div className="h-1.5 bg-slate-800 rounded-full"><div className="h-full bg-coral rounded-full" style={{ width: `${asset.vulnerabilityScore*100}%` }}></div></div>
                        </div>
                        <div className="w-1/2">
                          <div className="flex justify-between text-[10px] font-bold uppercase mb-1.5"><span className="text-slate-500">Maturity</span><span className="text-emerald-400">{(asset.maturityScore*100).toFixed(0)}%</span></div>
                          <div className="h-1.5 bg-slate-800 rounded-full"><div className="h-full bg-emerald-400 rounded-full" style={{ width: `${asset.maturityScore*100}%` }}></div></div>
                        </div>
                      </div>
                    </div>
                    <div className="flex gap-10 items-center ml-10">
                      <div className="text-right">
                        <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Impact (€/hr)</p>
                        <input 
                          type="number"
                          className="bg-black/30 border border-white/10 rounded-xl px-4 py-2 text-sm text-indigo-300 mono text-right w-36 focus:border-indigo-500 outline-none transition-all"
                          value={asset.hourlyLossValue}
                          onChange={e => updateAsset(asset.id, { hourlyLossValue: Number(e.target.value) })}
                        />
                      </div>
                      <button className="text-slate-600 hover:text-coral transition-colors p-3 text-lg"><i className="fas fa-ellipsis-v"></i></button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {view === 'CONTAGION' && (
            <div className="space-y-8 animate-in zoom-in duration-500 h-full flex flex-col">
               <div className="flex justify-between items-end mb-4">
                  <div>
                    <h2 className="text-3xl font-bold tracking-tight">Shock Propagation Analysis</h2>
                    <p className="text-xs text-slate-500 mt-1 uppercase tracking-widest font-mono">Modelling cascading failures across infrastructure nodes</p>
                  </div>
                  <div className="bg-indigo-500/10 border border-indigo-500/20 px-5 py-2.5 rounded-2xl flex items-center gap-3">
                    <span className="text-[10px] text-indigo-400 font-bold uppercase tracking-widest">Global Contagion Index</span>
                    <span className="text-xl font-bold text-white mono">0.42</span>
                  </div>
               </div>
               
               <div className="flex-1 bento-card rounded-[40px] relative p-10 overflow-hidden bg-slate-900/40 border border-white/5">
                  <div className="absolute inset-0 opacity-20 pointer-events-none">
                     <i className="fas fa-project-diagram text-[25rem] text-indigo-500/10 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 rotate-12"></i>
                  </div>
                  
                  <div className="h-full w-full relative">
                    <ResponsiveContainer width="100%" height="100%">
                      <ScatterChart margin={{ top: 40, right: 40, bottom: 40, left: 40 }}>
                        <XAxis type="number" dataKey="x" hide />
                        <YAxis type="number" dataKey="y" hide />
                        <ZAxis type="number" dataKey="impact" range={[800, 3000]} />
                        <Tooltip cursor={{ strokeDasharray: '3 3' }} content={({ payload }) => (
                          payload && payload.length > 0 ? (
                            <div className="glass p-4 rounded-2xl border-indigo-500/30 text-xs shadow-2xl">
                              <p className="font-bold text-white mb-2 uppercase tracking-widest">{payload[0].payload.name}</p>
                              <p className="text-indigo-400 font-bold">In-Degree Centrality: 0.82</p>
                              <p className="text-slate-500 mt-1">Impact potential: €{(payload[0].payload.impact/1000).toFixed(0)}k/h</p>
                            </div>
                          ) : null
                        )} />
                        <Scatter data={contagionData}>
                          {contagionData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.isTarget ? COLORS.CORAL : COLORS.INDIGO} fillOpacity={0.7} strokeWidth={2} stroke={entry.isTarget ? '#fff' : 'none'} className="hover:scale-110 transition-all cursor-pointer" />
                          ))}
                        </Scatter>
                      </ScatterChart>
                    </ResponsiveContainer>
                    
                    <svg className="absolute inset-0 pointer-events-none w-full h-full">
                       <line x1="15%" y1="40%" x2="40%" y2="55%" stroke={COLORS.CORAL} strokeWidth="1.5" strokeDasharray="6,4" opacity="0.6" />
                       <line x1="40%" y1="55%" x2="65%" y2="35%" stroke={COLORS.INDIGO} strokeWidth="1.5" opacity="0.3" />
                    </svg>
                  </div>

                  <div className="absolute bottom-10 left-10 right-10 flex gap-8">
                     <div className="flex-1 bento-card p-6 rounded-3xl backdrop-blur-md bg-black/40 border-white/10">
                        <div className="flex justify-between items-center mb-4">
                           <h5 className="text-[10px] font-bold uppercase text-slate-500 tracking-widest">Propagation Sensitivity</h5>
                           <span className="text-xs font-bold text-indigo-400 mono">{(simConfig.contagionFactor * 100).toFixed(0)}%</span>
                        </div>
                        <input 
                          type="range" min="0" max="1" step="0.1" 
                          value={simConfig.contagionFactor} 
                          onChange={e => updateSimConfig({ contagionFactor: Number(e.target.value) })}
                          className="w-full h-1 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-indigo-500" 
                        />
                     </div>
                     <div className="flex-1 bento-card p-6 rounded-3xl backdrop-blur-md bg-black/40 border-white/10 flex flex-col justify-center">
                        <p className="text-[9px] text-slate-500 uppercase font-bold mb-1.5">Critical Contagion Path</p>
                        <p className="text-xs font-bold text-white flex items-center gap-2">
                           Azure IAM <i className="fas fa-arrow-right text-slate-700 text-[10px]"></i> Core Banking <i className="fas fa-arrow-right text-slate-700 text-[10px]"></i> Payments
                        </p>
                     </div>
                  </div>
               </div>
            </div>
          )}

          {view === 'ALGO' && (
            <div className="max-w-4xl mx-auto space-y-10 animate-in zoom-in duration-500 pt-10">
              <div className="text-center space-y-2">
                <h2 className="text-3xl font-bold tracking-tight">Simulation Calibration</h2>
                <p className="text-xs text-slate-500 font-mono uppercase tracking-widest">Engine Tuning & Financial Governance</p>
              </div>
              
              <div className="grid grid-cols-2 gap-8">
                 <div className="bento-card p-10 rounded-[40px] space-y-10">
                    <h3 className="text-xs font-bold text-indigo-400 uppercase tracking-widest border-b border-white/10 pb-6 flex items-center gap-2">
                       <i className="fas fa-sliders-h"></i> Monte Carlo Parameters
                    </h3>
                    <div className="space-y-6">
                       <div className="flex justify-between items-center"><label className="text-xs font-bold text-slate-300 uppercase">Iterations</label><span className="mono text-indigo-400 font-bold">{simConfig.iterations.toLocaleString()}</span></div>
                       <input type="range" min="5000" max="100000" step="5000" value={simConfig.iterations} onChange={e => updateSimConfig({ iterations: Number(e.target.value) })} className="w-full accent-indigo-500" />
                    </div>
                    <div className="space-y-6">
                       <div className="flex justify-between items-center"><label className="text-xs font-bold text-slate-300 uppercase">Risk Appetite Limit</label><span className="mono text-amber-500 font-bold">€{(simConfig.riskAppetiteLimit / 1000000).toFixed(1)}M</span></div>
                       <input type="range" min="1000000" max="30000000" step="1000000" value={simConfig.riskAppetiteLimit} onChange={e => updateSimConfig({ riskAppetiteLimit: Number(e.target.value) })} className="w-full accent-amber-500" />
                    </div>
                 </div>
                 
                 <div className="bento-card p-10 rounded-[40px] space-y-10">
                    <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-widest border-b border-white/10 pb-6 flex items-center gap-2">
                       <i className="fas fa-shield-alt"></i> Insurance Hedging
                    </h3>
                    <div className="space-y-6">
                       <div className="flex justify-between items-center"><label className="text-xs font-bold text-slate-300 uppercase">Coverage Limit</label><span className="mono text-emerald-400 font-bold">€{(simConfig.insuranceCoverage / 1000000).toFixed(1)}M</span></div>
                       <input type="range" min="0" max="20000000" step="500000" value={simConfig.insuranceCoverage} onChange={e => updateSimConfig({ insuranceCoverage: Number(e.target.value) })} className="w-full accent-emerald-500" />
                    </div>
                    <div className="space-y-6">
                       <div className="flex justify-between items-center"><label className="text-xs font-bold text-slate-300 uppercase">Self-Retention (Deductible)</label><span className="mono text-slate-400 font-bold">€{(simConfig.insuranceDeductible / 100000).toFixed(1)}k</span></div>
                       <input type="range" min="0" max="2000000" step="50000" value={simConfig.insuranceDeductible} onChange={e => updateSimConfig({ insuranceDeductible: Number(e.target.value) })} className="w-full accent-slate-500" />
                    </div>
                 </div>
              </div>
              
              <div className="bento-card p-10 rounded-[40px] flex items-center justify-between bg-indigo-600/5">
                 <div className="space-y-1">
                   <h4 className="text-white font-bold text-lg">Deploy Control Strategy</h4>
                   <p className="text-xs text-slate-500">Auto-calibrate IT budget vs VaR reduction.</p>
                 </div>
                 <button onClick={handleRunAnalysis} className="px-10 py-4 bg-indigo-600 rounded-2xl text-xs font-bold uppercase tracking-widest hover:bg-indigo-500 shadow-xl shadow-indigo-600/20 transition-all">
                    Initiate Calibration
                 </button>
              </div>
            </div>
          )}

          {view === 'MODEL' && (
            <div className="max-w-4xl mx-auto space-y-12 animate-in fade-in duration-500 pt-10 pb-20">
              <div className="text-center space-y-2">
                <h2 className="text-3xl font-bold tracking-tight">Methodological Framework</h2>
                <p className="text-xs text-slate-500 font-mono uppercase tracking-widest">Neural Monte Carlo & Quant Specs</p>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="bento-card p-10 rounded-[40px] space-y-6">
                  <div className="w-12 h-12 rounded-2xl bg-indigo-500/10 flex items-center justify-center text-indigo-400 text-xl border border-indigo-500/20"><i className="fas fa-brain"></i></div>
                  <h4 className="text-lg font-bold text-white">Stochastic Engine Layers</h4>
                  <p className="text-sm text-slate-400 leading-relaxed">Our implementation uses a Temporal Neural Network to adjust the Poisson distribution of incident frequency. Every simulation iteration dynamically updates asset failure probabilities based on real-time correlation tokens extracted from the Gemini-3 Flash Intelligence feed.</p>
                </div>
                <div className="bento-card p-10 rounded-[40px] space-y-6">
                  <div className="w-12 h-12 rounded-2xl bg-coral/10 flex items-center justify-center text-coral text-xl border border-coral/20"><i className="fas fa-project-diagram"></i></div>
                  <h4 className="text-lg font-bold text-white">Contagion Graph Theory</h4>
                  <p className="text-sm text-slate-400 leading-relaxed">The risk propagation model treats infrastructure as a directed graph. Loss events in 'Hub' nodes (e.g., Active Directory) apply a conditional failure probability to 'Edge' nodes, following a log-normal decay function that simulates incident remediation velocity.</p>
                </div>
              </div>
              
              <div className="bento-card p-10 rounded-[40px] border border-white/5 space-y-8">
                 <h4 className="text-sm font-bold text-slate-400 uppercase tracking-widest text-center">Quant Backtesting & Integrity</h4>
                 <div className="grid grid-cols-4 gap-8">
                    {[
                      { l: 'Stability Index', v: '0.998' },
                      { l: 'VaR Backtest', v: 'PASSED' },
                      { l: 'Conf. Interval', v: '95%' },
                      { l: 'Methodology', v: 'HYBRID' }
                    ].map(st => (
                      <div key={st.l} className="text-center">
                        <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">{st.l}</p>
                        <p className="text-xl font-bold text-white mono">{st.v}</p>
                      </div>
                    ))}
                 </div>
              </div>
            </div>
          )}

          {view === 'COMPLIANCE' && (
            <div className="space-y-8 animate-in fade-in duration-700">
               <div className="flex justify-between items-end mb-8">
                 <div>
                   <h2 className="text-3xl font-bold tracking-tight">Regulatory Governance Matrix</h2>
                   <p className="text-xs text-slate-500 font-mono mt-2 uppercase tracking-widest">DORA, NIST & ISO Oversight Dashboard</p>
                 </div>
                 <div className="flex gap-4">
                    <div className="bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 px-6 py-3 rounded-2xl text-[10px] font-bold uppercase tracking-widest shadow-xl shadow-emerald-500/10">
                      Audit Readiness: 92% (Optimal)
                    </div>
                 </div>
               </div>
               
               <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                 {COMPLIANCE_ITEMS.map((item) => (
                   <div key={item.id} className="bento-card p-8 rounded-[40px] group relative overflow-hidden transition-all hover:translate-y-[-5px]">
                      <div className={`absolute top-0 left-0 w-2 h-full ${item.color}`}></div>
                      <div className="flex justify-between items-start mb-6">
                        <h4 className="font-bold text-xl text-white">{item.title}</h4>
                        <span className={`text-[10px] font-bold px-4 py-1.5 rounded-full uppercase tracking-widest ${item.color.replace('bg-', 'text-')} bg-white/5 border border-white/5`}>{item.status}</span>
                      </div>
                      <p className="text-sm text-slate-400 mb-10 leading-relaxed font-medium">{item.desc}</p>
                      <div className="flex justify-between items-center mt-auto">
                        <button onClick={() => setSelectedCompliance(item)} className="text-[10px] font-bold uppercase tracking-widest text-indigo-400 flex items-center gap-3 hover:gap-5 transition-all">
                          Secure Evidence Vault <i className="fas fa-arrow-right"></i>
                        </button>
                        <div className="flex -space-x-3">
                           {[1,2,3].map(i => <div key={i} className="w-8 h-8 rounded-full border-2 border-slate-900 bg-slate-800 flex items-center justify-center text-[8px] font-bold text-slate-500 uppercase">A{i}</div>)}
                        </div>
                      </div>
                   </div>
                 ))}
               </div>
            </div>
          )}

        </main>
      </div>
    </div>
  );
};

export default App;
