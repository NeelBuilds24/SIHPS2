import React, { useState } from 'react';
import { Sidebar, PageId } from './components/Sidebar';
import { Header } from './components/Header';
import { Overview } from './pages/Overview';
import { LiveDetection } from './pages/LiveDetection';
import { AttackChains } from './pages/AttackChains';
import { AttackGraph } from './pages/AttackGraph';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { ThreatDetails } from './pages/ThreatDetails';
import { Forecast } from './pages/Forecast';
import { AdaptiveBaseline } from './pages/AdaptiveBaseline';
import { AuditTrail } from './pages/AuditTrail';
import { ModelPerformance } from './pages/ModelPerformance';
import { SettingsUpload } from './pages/SettingsUpload';
import { ThreatType } from './types';

export function App() {
  const [currentPage, setCurrentPage] = useState<PageId | 'threat-details'>('overview');
  const [selectedThreatType, setSelectedThreatType] = useState<ThreatType>('DNS_TUNNEL');

  const handleSelectThreat = (threat: ThreatType) => {
    setSelectedThreatType(threat);
    setCurrentPage('threat-details');
  };

  const renderPage = () => {
    switch (currentPage) {
      case 'overview':
        return <Overview />;
      case 'live-detection':
        return <LiveDetection />;
      case 'attack-chains':
        return <AttackChains />;
      case 'attack-graph':
        return <AttackGraph />;
      case 'threat-intel':
        return <ThreatIntelligence onSelectThreat={handleSelectThreat} />;
      case 'threat-details':
        return <ThreatDetails threatType={selectedThreatType} onBack={() => setCurrentPage('threat-intel')} />;
      case 'forecast':
        return <Forecast />;
      case 'baseline':
        return <AdaptiveBaseline />;
      case 'audit-trail':
        return <AuditTrail />;
      case 'model-performance':
        return <ModelPerformance />;
      case 'settings':
        return <SettingsUpload />;
      default:
        return <Overview />;
    }
  };

  return (
    <div className="flex min-h-screen bg-background text-slate-100 font-sans">
      <Sidebar currentPage={currentPage === 'threat-details' ? 'threat-intel' : currentPage} onSelectPage={p => setCurrentPage(p)} />
      <div className="flex-1 flex flex-col min-w-0">
        <Header />
        <main className="p-6 flex-1 overflow-y-auto">
          {renderPage()}
        </main>
      </div>
    </div>
  );
}

export default App;
