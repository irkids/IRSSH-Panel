import { useState, useEffect } from 'react';
import { processChartData } from '../utils/chartHelpers';

export const useChartData = (metrics, timeRange = '1h') => {
  const [chartData, setChartData] = useState([]);
  const [timeScale, setTimeScale] = useState(timeRange);

  useEffect(() => {
    const data = processChartData(metrics, timeScale);
    setChartData(data);
  }, [metrics, timeScale]);

  const updateTimeScale = (newScale) => {
    setTimeScale(newScale);
  };

  return { chartData, timeScale, updateTimeScale };
};
