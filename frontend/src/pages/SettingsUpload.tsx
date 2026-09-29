import React, { useState } from 'react';
import { Upload, Settings as SettingsIcon, FileText, CheckCircle, AlertCircle, Play } from 'lucide-react';
import { api } from '../services/api';

export const SettingsUpload: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [uploadStatus, setUploadStatus] = useState<string>('');
  const [uploading, setUploading] = useState<boolean>(false);
  const [resultAlerts, setResultAlerts] = useState<any[]>([]);

  // Threshold Settings State
  const [detectionThreshold, setDetectionThreshold] = useState<number>(70);
  const [anomalySensitivity, setAnomalySensitivity] = useState<number>(65);
  const [learningRate, setLearningRate] = useState<number>(5);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setUploadStatus('READY FOR ANALYSIS');
    }
  };

  const handleUploadAndAnalyze = async () => {
    if (!file) return;
    setUploading(true);
    setUploadStatus('PROCESSING PASSIVE ANALYSIS PIPELINE...');
    try {
      const res = await api.uploadCSV(file);
      setResultAlerts(res.alerts || []);
      setUploadStatus(`ANALYSIS COMPLETE! Processed ${res.total_rows_processed} flows.`);
    } catch (err: any) {
      setUploadStatus(`ERROR: ${err?.response?.data?.detail || 'Failed to process CSV file'}`);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100 font-mono tracking-wide">
          Settings & Dataset Upload
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Upload PCAP-derived flow CSVs for passive analysis and configure enclave risk scoring thresholds
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* React Drag & Drop CSV Uploader */}
        <div className="soc-card p-6 space-y-4">
          <h3 className="text-sm font-bold text-slate-200 font-mono uppercase tracking-wide flex items-center gap-2 border-b border-border pb-3">
            <Upload className="w-4 h-4 text-cyan-400" /> Upload Passive Traffic Dataset (CSV)
          </h3>

          <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500 rounded-lg p-8 text-center transition bg-slate-950/40">
            <input
              type="file"
              accept=".csv"
              id="file-upload"
              onChange={handleFileChange}
              className="hidden"
            />
            <label htmlFor="file-upload" className="cursor-pointer flex flex-col items-center">
              <FileText className="w-12 h-12 text-cyan-400 mb-3 animate-bounce" />
              <span className="text-sm font-bold text-slate-200">
                {file ? file.name : 'Drop CSV file here, or click to browse'}
              </span>
              <span className="text-xs text-slate-500 mt-1">
                Supports PCAP-derived metadata, NetFlow, IPFIX, sFlow, or CICFlowMeter CSVs
              </span>
            </label>
          </div>

          {file && (
            <div className="p-4 bg-slate-900 border border-border rounded-lg font-mono text-xs space-y-2">
              <div className="flex justify-between">
                <span className="text-slate-400">File Name:</span>
                <span className="font-bold text-cyan-300">{file.name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Size:</span>
                <span className="font-bold text-slate-200">{(file.size / 1024).toFixed(1)} KB</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Status:</span>
                <span className="font-bold text-emerald-400">{uploadStatus}</span>
              </div>

              <button
                onClick={handleUploadAndAnalyze}
                disabled={uploading}
                className="w-full mt-3 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-black font-bold rounded-lg transition flex items-center justify-center gap-2 shadow-[0_0_12px_rgba(0,240,255,0.3)]"
              >
                <Play className="w-4 h-4 fill-current" /> {uploading ? 'Analyzing Flows...' : 'ANALYZE PASSIVE DATA'}
              </button>
            </div>
          )}

          {resultAlerts.length > 0 && (
            <div className="mt-4">
              <div className="text-xs font-bold text-slate-300 font-mono mb-2">
                Analyzed Threat Preview (Top {resultAlerts.length})
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {resultAlerts.map(alert => (
                  <div key={alert.alert_id} className="p-2.5 bg-slate-900 border border-slate-800 rounded text-xs font-mono flex items-center justify-between">
                    <div>
                      <span className="font-bold text-slate-100">{alert.threat}</span>
                      <span className="text-slate-500 ml-2">[{alert.src_ip}]</span>
                    </div>
                    <span className="font-bold text-red-400">Risk: {alert.risk_score.toFixed(0)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Configuration Settings */}
        <div className="soc-card p-6 space-y-6">
          <h3 className="text-sm font-bold text-slate-200 font-mono uppercase tracking-wide flex items-center gap-2 border-b border-border pb-3">
            <SettingsIcon className="w-4 h-4 text-purple-400" /> Enclave Scoring & Threshold Settings
          </h3>

          <div className="space-y-5 font-mono text-xs">
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300">Detection Risk Threshold:</span>
                <span className="font-bold text-cyan-400">{detectionThreshold} / 100</span>
              </div>
              <input
                type="range"
                min={30}
                max={90}
                value={detectionThreshold}
                onChange={e => setDetectionThreshold(Number(e.target.value))}
                className="w-full h-2 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-cyan-400"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300">Anomaly Sensitivity (Isolation Forest):</span>
                <span className="font-bold text-amber-400">{anomalySensitivity}%</span>
              </div>
              <input
                type="range"
                min={30}
                max={95}
                value={anomalySensitivity}
                onChange={e => setAnomalySensitivity(Number(e.target.value))}
                className="w-full h-2 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-amber-400"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300">Adaptive Baseline Learning Rate (EMA Alpha):</span>
                <span className="font-bold text-emerald-400">{learningRate}%</span>
              </div>
              <input
                type="range"
                min={1}
                max={20}
                value={learningRate}
                onChange={e => setLearningRate(Number(e.target.value))}
                className="w-full h-2 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-emerald-400"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
