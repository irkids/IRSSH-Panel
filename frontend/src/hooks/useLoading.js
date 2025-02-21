import { useState, useCallback } from 'react';

export const useLoading = (initialState = false) => {
  const [loading, setLoading] = useState(initialState);
  const [error, setError] = useState(null);

  const startLoading = useCallback(() => {
    setLoading(true);
    setError(null);
  }, []);

  const stopLoading = useCallback(() => {
    setLoading(false);
  }, []);

  const withLoading = useCallback(async (callback) => {
    try {
      startLoading();
      await callback();
    } catch (err) {
      setError(err);
      throw err;
    } finally {
      stopLoading();
    }
  }, [startLoading, stopLoading]);

  return {
    loading,
    error,
    startLoading,
    stopLoading,
    withLoading
  };
};
