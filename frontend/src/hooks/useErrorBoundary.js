import { useState, useCallback } from 'react';

export const useErrorBoundary = () => {
  const [error, setError] = useState(null);

  const resetError = useCallback(() => {
    setError(null);
  }, []);

  const handleError = useCallback((error) => {
    setError(error);
    // Log error to monitoring service
    console.error('Error caught by boundary:', error);
  }, []);

  return {
    error,
    resetError,
    handleError
  };
};
