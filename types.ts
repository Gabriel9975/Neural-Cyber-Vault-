
export enum AssetType {
  PAYMENT_SYSTEM = 'Payment System',
  DATABASE = 'Database',
  TRADING_ALGO = 'Trading Algorithm',
  CLOUD_INFRA = 'Cloud Infrastructure',
  IDENTITY_PROVIDER = 'IAM Provider'
}

export type ViewType = 'DASHBOARD' | 'CONTAGION' | 'ASSETS' | 'CAPITAL' | 'ALGO' | 'MODEL' | 'COMPLIANCE';

export interface Asset {
  id: string;
  name: string;
  type: AssetType;
  hourlyLossValue: number;
  baseProbability: number;
  technologies: string[];
  dependencies?: string[];
  vulnerabilityScore: number;
  maturityScore: number;
}

export interface Control {
  id: string;
  name: string;
  cost: number;
  varReduction: number; // Percentage reduction (0.0 - 1.0)
  mapping: 'NIST' | 'ISO27001' | 'DORA';
  implemented: boolean;
}

export interface Threat {
  id: string;
  title: string;
  description: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  targetTechnology: string;
  impactModifier: number;
  timestamp: string;
}

export type StressScenario = 'NONE' | 'RANSOMWARE_WAVE' | 'ZERO_DAY_MASSIVE' | 'SUPPLY_CHAIN_COLLAPSE';

export interface SimulationConfig {
  iterations: number;
  confidenceInterval: number;
  horizonDays: number;
  stressScenario: StressScenario;
  netIncome: number;
  itSecurityBudget: number;
  riskAppetiteLimit: number;
  insuranceCoverage: number;
  insuranceDeductible: number;
  useNeuralAdjustments: boolean;
  contagionFactor: number;
}

export interface HorizonResult {
  days: number;
  varValue: number;
  cvarValue: number;
  classicVarValue: number;
}

export interface XAIDriver {
  name: string;
  impact: number;
  type: 'ASSET' | 'THREAT' | 'TECH' | 'CONTROL';
}

export interface SimulationResult {
  var95: number;
  var99: number; // Worst 1%
  cvar95: number;
  expectedLoss: number;
  maxLoss: number;
  totalLosses: number[];
  assetBreaks: {
    assetName: string;
    contribution: number;
    allocatedCapital: number;
    raroc: number;
  }[];
  horizons: HorizonResult[];
  drivers: XAIDriver[];
  narrative: string;
  breachStatus: 'SAFE' | 'WARNING' | 'BREACH';
  economicCapital: number;
}

export interface User {
  email: string;
  role: string;
  lastLogin: string;
  password?: string;
}

export interface ComplianceRequirement {
  id: string;
  title: string;
  desc: string;
  status: 'Done' | 'Pending';
  color: string;
  evidence: string[];
}
