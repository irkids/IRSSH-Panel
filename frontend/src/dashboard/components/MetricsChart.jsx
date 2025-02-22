import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import { useMetricsContext } from '../context/MetricsContext';

const MetricsChart = () => {
  const { state } = useMetricsContext();
  const { metrics } = state;

  return (
    <div className="p-4 bg-white rounded-lg shadow">
      <LineChart width={800} height={400} data={metrics.timeSeries}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="timestamp" />
        <YAxis />
        <Tooltip />
        <Legend />
        <Line type="monotone" dataKey="cpu" stroke="#8884d8" />
        <Line type="monotone" dataKey="memory" stroke="#82ca9d" />
        <Line type="monotone" dataKey="network" stroke="#ffc658" />
      </LineChart>
    </div>
  );
};

export default MetricsChart;
