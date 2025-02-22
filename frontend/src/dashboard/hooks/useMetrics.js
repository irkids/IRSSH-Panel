import { useState, useEffect } from 'react';
import { fetchMetrics } from '../services/metricsApi';

export const useMetrics = (interval = 5000) => {
  const [metrics, setMetrics] = useState({
    cpu: 0,
    memory: 0,
    network: { in: 0, out: 0 },
    connections: 0
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await fetchMetrics();
        setMetrics(data);
        setLoading(false);
      } catch (err) {
        setError(err);
        setLoading(false);
      }
    };

    fetchData();
    const timer = setInterval(fetchData, interval);

    return () => clearInterval(timer);
  }, [interval]);

  return { metrics, loading, error };
};
