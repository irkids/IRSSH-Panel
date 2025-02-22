import React from 'react';
import { useMetricsContext } from '../context/MetricsContext';

const MetricsToolbar = () => {
  const { state, dispatch } = useMetricsContext();
  const { filters } = state;

  const timeRanges = [
    { label: 'Last Hour', value: '1h' },
    { label: 'Last 6 Hours', value: '6h' },
    { label: 'Last Day', value: '24h' },
    { label: 'Last Week', value: '7d' }
  ];

  const handleTimeRangeChange = (range) => {
    dispatch({
      type: 'UPDATE_FILTERS',
      payload: { timeRange: range }
    });
  };

  return (
    <div className="flex items-center justify-between p-4 bg-white shadow rounded-lg">
      <div className="flex space-x-4">
        {timeRanges.map(({ label, value }) => (
          <button
            key={value}
            onClick={() => handleTimeRangeChange(value)}
            className={`px-4 py-2 rounded ${
              filters.timeRange === value
                ? 'bg-blue-600 text-white'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            {label}
          </button>
        ))}
      </div>
      
      <div className="flex items-center space-x-4">
        <button
          onClick={() => {/* Export functionality */}}
          className="px-4 py-2 text-gray-700 border rounded hover:bg-gray-50"
        >
          Export Data
        </button>
        
        <button
          onClick={() => {/* Settings functionality */}}
          className="px-4 py-2 text-gray-700 border rounded hover:bg-gray-50"
        >
          Settings
        </button>
      </div>
    </div>
  );
};

export default MetricsToolbar;
