import React from "react";

const AIInsights = ({ suggestions }) => {
  return (
    <div className="ai-insights">
      {suggestions.map((suggestion, index) => (
        <div key={index} className="insight-card">
          <h3>{suggestion.title}</h3>
          <p>{suggestion.description}</p>
          <pre>{suggestion.remediation}</pre>
        </div>
      ))}
    </div>
  );
};

export default AIInsights;