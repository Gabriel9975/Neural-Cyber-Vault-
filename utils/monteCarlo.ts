
import { Asset, Threat, SimulationResult, SimulationConfig, HorizonResult, XAIDriver } from '../types';

export const runMonteCarloSimulation = (
  assets: Asset[],
  threats: Threat[],
  config: SimulationConfig
): SimulationResult => {
  const iterations = config.iterations;
  const horizons = [1, 10, 30, config.horizonDays];
  const horizonResults: HorizonResult[] = [];
  
  let mainVar95 = 0;
  let mainVar99 = 0;
  let mainCvar95 = 0;
  let mainTotalLosses: number[] = [];
  let mainAssetBreaks: { assetName: string; contribution: number; allocatedCapital: number; raroc: number }[] = [];

  horizons.forEach(hDays => {
    const neuralLosses: number[] = [];
    const classicLosses: number[] = [];
    const assetImpactCounts: Record<string, number> = {};
    assets.forEach(a => assetImpactCounts[a.id] = 0);

    const horizonScale = hDays / 365;
    
    let freqMultiplier = 1.0;
    let severityMultiplier = 1.0;
    switch (config.stressScenario) {
      case 'RANSOMWARE_WAVE': freqMultiplier = 3.0; severityMultiplier = 1.8; break;
      case 'ZERO_DAY_MASSIVE': freqMultiplier = 2.2; severityMultiplier = 4.0; break;
      case 'SUPPLY_CHAIN_COLLAPSE': freqMultiplier = 1.6; severityMultiplier = 7.0; break;
    }

    for (let i = 0; i < iterations; i++) {
      let scenarioLossNeural = 0;
      let scenarioLossClassic = 0;
      const triggeredAssetsNeural = new Set<string>();
      const triggeredAssetsClassic = new Set<string>();

      assets.forEach(asset => {
        const classicProb = asset.baseProbability * horizonScale;
        if (Math.random() < classicProb) triggeredAssetsClassic.add(asset.id);

        let neuralProb = asset.baseProbability * horizonScale * freqMultiplier;
        neuralProb *= (1 + asset.vulnerabilityScore - asset.maturityScore);
        
        threats.forEach(t => {
          if (asset.technologies.includes(t.targetTechnology)) neuralProb *= t.impactModifier;
        });

        if (Math.random() < Math.min(0.99, neuralProb)) {
          triggeredAssetsNeural.add(asset.id);
        }
      });

      if (config.contagionFactor > 0) {
        let changed = true;
        let depth = 0;
        while (changed && depth < 5) {
          changed = false;
          depth++;
          assets.forEach(asset => {
            if (!triggeredAssetsNeural.has(asset.id) && asset.dependencies) {
              const triggeredDeps = asset.dependencies.filter(id => triggeredAssetsNeural.has(id));
              if (triggeredDeps.length > 0) {
                const propagationChance = config.contagionFactor * (1 - Math.pow(0.5, triggeredDeps.length));
                if (Math.random() < propagationChance) {
                  triggeredAssetsNeural.add(asset.id);
                  changed = true;
                }
              }
            }
          });
        }
      }

      triggeredAssetsNeural.forEach(id => {
        const asset = assets.find(a => a.id === id);
        if (asset) {
          const baseDuration = 4 + (Math.random() * 2 - 1) * 2;
          const duration = Math.max(0.5, baseDuration * severityMultiplier);
          const loss = duration * asset.hourlyLossValue;
          scenarioLossNeural += loss;
          if (hDays === config.horizonDays) assetImpactCounts[id] += loss;
        }
      });

      triggeredAssetsClassic.forEach(id => {
        const asset = assets.find(a => a.id === id);
        if (asset) {
          const duration = Math.max(0.5, (4 + (Math.random() * 2 - 1) * 2));
          const loss = duration * asset.hourlyLossValue;
          scenarioLossClassic += loss;
        }
      });

      const insuredLoss = Math.max(0, scenarioLossNeural - config.insuranceDeductible);
      const finalLoss = Math.max(0, scenarioLossNeural - Math.min(insuredLoss, config.insuranceCoverage));

      neuralLosses.push(config.useNeuralAdjustments ? finalLoss : scenarioLossClassic);
      classicLosses.push(scenarioLossClassic);
    }

    const sortedNeural = [...neuralLosses].sort((a, b) => a - b);
    const sortedClassic = [...classicLosses].sort((a, b) => a - b);
    const varIdx95 = Math.floor(iterations * 0.95);
    const varIdx99 = Math.floor(iterations * 0.99);
    
    const varVal95 = sortedNeural[varIdx95];
    const varVal99 = sortedNeural[varIdx99];
    const tail95 = sortedNeural.slice(varIdx95);
    const cvarVal95 = tail95.length > 0 ? tail95.reduce((a, b) => a + b, 0) / tail95.length : varVal95;
    const classicVarVal95 = sortedClassic[varIdx95];

    horizonResults.push({ days: hDays, varValue: varVal95, cvarValue: cvarVal95, classicVarValue: classicVarVal95 });

    if (hDays === config.horizonDays) {
      mainVar95 = varVal95;
      mainVar99 = varVal99;
      mainCvar95 = cvarVal95;
      mainTotalLosses = sortedNeural;
      
      const totalContribution = Object.values(assetImpactCounts).reduce((a, b) => a + b, 0) || 1;
      const ecMultiplier = 1.25; // Capital Buffer
      const totalEconomicCapital = mainVar95 * ecMultiplier;

      mainAssetBreaks = assets.map(a => {
        const contrib = assetImpactCounts[a.id] / iterations;
        const weight = (assetImpactCounts[a.id] / totalContribution);
        return {
          assetName: a.name,
          contribution: contrib,
          allocatedCapital: totalEconomicCapital * weight,
          raroc: (contrib > 0) ? (a.hourlyLossValue * 24 * 365 * 0.1) / (totalEconomicCapital * weight) : 0 // Simulated RAROC
        };
      }).sort((a, b) => b.contribution - a.contribution);
    }
  });

  const breachStatus = mainVar95 > config.riskAppetiteLimit ? 'BREACH' : (mainVar95 > config.riskAppetiteLimit * 0.8 ? 'WARNING' : 'SAFE');
  const drivers: XAIDriver[] = [
    { name: mainAssetBreaks[0]?.assetName || 'Asset Loss', impact: 0.75, type: 'ASSET' },
    { name: threats[0]?.title || 'Threat Feed', impact: 0.55, type: 'THREAT' },
    { name: 'Capital Sensitivity', impact: 0.4, type: 'CONTROL' }
  ];

  return {
    var95: mainVar95,
    var99: mainVar99,
    cvar95: mainCvar95,
    expectedLoss: mainTotalLosses.reduce((a,b)=>a+b,0)/iterations,
    maxLoss: mainTotalLosses[iterations-1],
    totalLosses: mainTotalLosses,
    assetBreaks: mainAssetBreaks,
    horizons: horizonResults,
    drivers,
    narrative: `Neural engine complete. Critical VaR (99%) €${(mainVar99/1000000).toFixed(2)}M requires an Economic Capital buffer of €${((mainVar95*1.25)/1000000).toFixed(2)}M. Statut: ${breachStatus}.`,
    breachStatus,
    economicCapital: mainVar95 * 1.25
  };
};
