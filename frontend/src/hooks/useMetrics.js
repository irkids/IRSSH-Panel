import { useState, useEffect } from 'react';
import { metricsService } from '../services/metrics';

export const useMetrics = (type, interval = 5000) => {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let timeoutId;

    const fetchMetrics = async () => {
      try {
        setLoading(true);
        const data = await metricsService.getMetrics(type);
        setMetrics(data);
        setError(null);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    const poll = () => {
      fetchMetrics();
      timeoutId = setTimeout(poll, interval);
    };

    poll();

    return () => {
      clearTimeout(timeoutId);
    };
  }, [type, interval]);

  return { metrics, loading, error };
};
