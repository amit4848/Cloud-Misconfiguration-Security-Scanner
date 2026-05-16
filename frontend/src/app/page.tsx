'use client';

import { useState, useEffect } from 'react';

export default function Dashboard() {
  const [loading, setLoading] = useState(false);
  const [scanData, setScanData] = useState<any>(null);
  
  const [iacLoading, setIacLoading] = useState(false);
  const [iacData, setIacData] = useState<any>(null);
  
  const [history, setHistory] = useState<any[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/history');
      if (res.ok) {
        const result = await res.json();
        setHistory(result.data);
      }
    } catch (err) {
      console.error("Failed to load history");
    }
  };

  const runScan = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch('http://localhost:8000/api/scan');
      if (!response.ok) throw new Error('Failed to fetch scan results');
      const result = await response.json();
      setScanData(result.data);
      fetchHistory();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const runIacScan = async () => {
    setIacLoading(true);
    setError('');
    try {
      const response = await fetch('http://localhost:8000/api/scan-iac');
      if (!response.ok) throw new Error('Failed to fetch IaC results');
      const result = await response.json();
      setIacData(result.data.iac_results);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIacLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-gray-50 p-8 text-gray-900">
      <div className="max-w-6xl mx-auto space-y-8">
        
        {/* Header Section */}
        <header className="flex justify-between items-center border-b pb-6">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Cloud Security Posture</h1>
            <p className="text-gray-500 mt-1">Multi-Cloud DevSecOps Auditor</p>
          </div>
          <div className="flex gap-4">
            <button 
              onClick={runIacScan}
              disabled={iacLoading}
              className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-2 rounded-lg font-medium transition-all disabled:opacity-50 shadow-sm"
            >
              {iacLoading ? 'Reading Code...' : 'Scan Terraform (IaC)'}
            </button>
            <button 
              onClick={runScan}
              disabled={loading}
              className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-medium transition-all disabled:opacity-50 shadow-sm"
            >
              {loading ? 'Scanning Clouds...' : 'Scan Live Environments'}
            </button>
          </div>
        </header>

        {error && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
            <strong>Connection Error: </strong> {error}
          </div>
        )}

        {/* Shift-Left IaC Results Panel */}
        {iacData && (
          <div className="bg-white p-6 rounded-xl shadow-sm border border-purple-200">
            <h2 className="text-xl font-semibold mb-4 border-b pb-2 text-purple-800">Shift-Left: Terraform Code Scan</h2>
            <ul className="space-y-3">
              {iacData.map((item: any, idx: number) => (
                <li key={idx} className="flex flex-col p-4 rounded-md bg-purple-50 border border-purple-100">
                  <div className="flex justify-between">
                    <span className="font-mono text-sm font-semibold truncate max-w-[70%]">{item.resource}</span>
                    <span className={`text-xs font-bold px-3 py-1 rounded-full ${item.status === 'SECURE' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700 animate-pulse'}`}>{item.status}</span>
                  </div>
                  <span className="text-sm text-gray-600 mt-2">{item.details}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Current Live Cloud Scan Results */}
        {scanData && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* AWS S3 Column */}
            <div className="bg-white p-6 rounded-xl shadow-sm border border-orange-100">
              <h2 className="text-xl font-semibold mb-4 border-b pb-2">AWS: S3 Buckets</h2>
              {scanData.s3_results?.length === 0 ? <p className="text-gray-500 text-sm">No buckets found.</p> : (
                <ul className="space-y-3">
                  {scanData.s3_results?.map((item: any, idx: number) => (
                    <li key={idx} className="flex flex-col p-3 rounded-md bg-gray-50 border">
                      <div className="flex justify-between">
                        <span className="font-mono text-sm truncate max-w-[60%]">{item.resource}</span>
                        <span className={`text-xs font-bold px-2 py-1 rounded-full ${item.status === 'SECURE' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>{item.status}</span>
                      </div>
                      <span className="text-xs text-gray-500 mt-1">{item.details}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* AWS EC2 SG Column */}
            <div className="bg-white p-6 rounded-xl shadow-sm border border-orange-100">
              <h2 className="text-xl font-semibold mb-4 border-b pb-2">AWS: EC2 Firewalls</h2>
              {scanData.ec2_results?.length === 0 ? <p className="text-gray-500 text-sm">No security groups found.</p> : (
                <ul className="space-y-3">
                  {scanData.ec2_results?.map((item: any, idx: number) => (
                    <li key={idx} className="flex flex-col p-3 rounded-md bg-gray-50 border">
                      <div className="flex justify-between">
                        <span className="font-mono text-sm truncate max-w-[60%]">{item.resource}</span>
                        <span className={`text-xs font-bold px-2 py-1 rounded-full ${item.status === 'SECURE' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>{item.status}</span>
                      </div>
                      <span className="text-xs text-gray-500 mt-1">{item.details}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* AWS IAM Column */}
            <div className="bg-white p-6 rounded-xl shadow-sm border border-orange-100">
              <h2 className="text-xl font-semibold mb-4 border-b pb-2">AWS: IAM Users</h2>
              {scanData.iam_results?.length === 0 ? <p className="text-gray-500 text-sm">No IAM users found.</p> : (
                <ul className="space-y-3">
                  {scanData.iam_results?.map((item: any, idx: number) => (
                    <li key={idx} className="flex flex-col p-3 rounded-md bg-gray-50 border">
                      <div className="flex justify-between">
                        <span className="font-mono text-sm truncate max-w-[60%]">{item.resource}</span>
                        <span className={`text-xs font-bold px-2 py-1 rounded-full ${item.status === 'SECURE' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>{item.status}</span>
                      </div>
                      <span className="text-xs text-gray-500 mt-1">{item.details}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* AWS EC2 Instances Column */}
            <div className="bg-white p-6 rounded-xl shadow-sm border border-orange-100">
              <h2 className="text-xl font-semibold mb-4 border-b pb-2">AWS: EC2 (IMDSv2)</h2>
              {scanData.ec2_imds_results?.length === 0 ? <p className="text-gray-500 text-sm">No instances found.</p> : (
                <ul className="space-y-3">
                  {scanData.ec2_imds_results?.map((item: any, idx: number) => (
                    <li key={idx} className="flex flex-col p-3 rounded-md bg-gray-50 border">
                      <div className="flex justify-between">
                        <span className="font-mono text-sm truncate max-w-[60%]">{item.resource}</span>
                        <span className={`text-xs font-bold px-2 py-1 rounded-full ${item.status === 'SECURE' ? 'bg-green-100 text-green-700' : item.status === 'WARNING' ? 'bg-yellow-100 text-yellow-700' : 'bg-red-100 text-red-700'}`}>{item.status}</span>
                      </div>
                      <span className="text-xs text-gray-500 mt-1">{item.details}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* NEW: Azure Storage Column */}
            <div className="bg-white p-6 rounded-xl shadow-sm border border-blue-200">
              <h2 className="text-xl font-semibold mb-4 border-b pb-2 text-blue-800">Azure: Storage Accounts</h2>
              {scanData.azure_storage_results?.length === 0 ? <p className="text-gray-500 text-sm">No storage accounts found.</p> : (
                <ul className="space-y-3">
                  {scanData.azure_storage_results?.map((item: any, idx: number) => (
                    <li key={idx} className="flex flex-col p-3 rounded-md bg-blue-50 border border-blue-100">
                      <div className="flex justify-between">
                        <span className="font-mono text-sm truncate max-w-[60%] text-blue-900">{item.resource}</span>
                        <span className={`text-xs font-bold px-2 py-1 rounded-full ${item.status === 'SECURE' ? 'bg-green-100 text-green-700' : item.status === 'WARNING' ? 'bg-yellow-100 text-yellow-700' : item.status === 'ERROR' ? 'bg-gray-200 text-gray-800' : 'bg-red-100 text-red-700'}`}>{item.status}</span>
                      </div>
                      <span className="text-xs text-gray-600 mt-1">{item.details}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            {/* NEW: Azure NSG Column */}
            <div className="bg-white p-6 rounded-xl shadow-sm border border-blue-200">
              <h2 className="text-xl font-semibold mb-4 border-b pb-2 text-blue-800">Azure: Network Security Groups</h2>
              {scanData.azure_nsg_results?.length === 0 ? <p className="text-gray-500 text-sm">No security groups found.</p> : (
                <ul className="space-y-3">
                  {scanData.azure_nsg_results?.map((item: any, idx: number) => (
                    <li key={idx} className="flex flex-col p-3 rounded-md bg-blue-50 border border-blue-100">
                      <div className="flex justify-between">
                        <span className="font-mono text-sm truncate max-w-[60%] text-blue-900">{item.resource}</span>
                        <span className={`text-xs font-bold px-2 py-1 rounded-full ${item.status === 'SECURE' ? 'bg-green-100 text-green-700' : item.status === 'WARNING' ? 'bg-yellow-100 text-yellow-700' : item.status === 'ERROR' ? 'bg-gray-200 text-gray-800' : 'bg-red-100 text-red-700'}`}>{item.status}</span>
                      </div>
                      <span className="text-xs text-gray-600 mt-1">{item.details}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

          </div>
        )}

        {/* Scan History Table */}
        <div className="bg-white p-6 rounded-xl shadow-sm border mt-8">
          <h2 className="text-xl font-semibold mb-4 border-b pb-2">Recent Multi-Cloud Scan History</h2>
          {history.length === 0 ? (
            <p className="text-gray-500 text-sm italic">No past live scans found in the database.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm text-left">
                <thead className="text-xs text-gray-500 uppercase bg-gray-50">
                  <tr>
                    <th className="px-6 py-3">Timestamp (Local)</th>
                    <th className="px-6 py-3">AWS S3</th>
                    <th className="px-6 py-3">AWS EC2 (SG)</th>
                    <th className="px-6 py-3">AWS IAM</th>
                    <th className="px-6 py-3">AWS EC2 (VM)</th>
                    <th className="px-6 py-3 text-blue-700">Azure Storage</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((scan: any, idx: number) => (
                    <tr key={idx} className="bg-white border-b hover:bg-gray-50">
                      <td className="px-6 py-4 font-mono">{new Date(scan.timestamp).toLocaleString()}</td>
                      <td className="px-6 py-4">{scan.results.s3_results?.length || 0}</td>
                      <td className="px-6 py-4">{scan.results.ec2_results?.length || 0}</td>
                      <td className="px-6 py-4">{scan.results.iam_results?.length || 0}</td>
                      <td className="px-6 py-4">{scan.results.ec2_imds_results?.length || 0}</td>
                      <td className="px-6 py-4 font-bold text-blue-700">{scan.results.azure_storage_results?.length || 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </div>
    </main>
  );
}

