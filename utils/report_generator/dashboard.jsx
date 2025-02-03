import React, { useState, useEffect } from "react";
import { Chart, Graph, AIInsights } from "./components";

const Dashboard = ({ findings }) => {
  const [reportData, setReportData] = useState(null);
  const [aiSuggestions, setAiSuggestions] = useState([]);

  useEffect(() => {
    // Process findings for visualization
    const processedData = processFindings(findings);
    setReportData(processedData);

    // Fetch AI-generated insights
    fetchAISuggestions(findings).then(setAiSuggestions);
  }, [findings]);

  const processFindings = (data) => {
    // Transform findings for charts and graphs
    return {
      vulnerabilities: data.vulnerabilities,
      attackPaths: data.attackPaths,
      dataLeaks: data.dataLeaks,
    };
  };

  const fetchAISuggestions = async (data) => {
    // Call AI API for remediation suggestions
    const response = await fetch("/api/ai/insights", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return response.json();
  };

  return (
    <div className="dashboard">
      <h1>SentinelForge Security Report</h1>

      {/* Vulnerability Overview */}
      <section>
        <h2>Vulnerability Overview</h2>
        <Chart data={reportData?.vulnerabilities} type="bar" />
      </section>

      {/* Attack Path Visualization */}
      <section>
        <h2>Attack Paths</h2>
        <Graph data={reportData?.attackPaths} />
      </section>

      {/* Data Leaks */}
      <section>
        <h2>Data Leaks</h2>
        <ul>
          {reportData?.dataLeaks.map((leak, index) => (
            <li key={index}>{leak}</li>
          ))}
        </ul>
      </section>

      {/* AI-Powered Insights */}
      <section>
        <h2>AI Recommendations</h2>
        <AIInsights suggestions={aiSuggestions} />
      </section>
    </div>
  );
};

export default Dashboard;