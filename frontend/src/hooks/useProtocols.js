import { useState, useEffect } from 'react';
import { protocolService } from '../services/protocols';

export const useProtocols = () => {
  const [protocols, setProtocols] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchProtocols();
  }, []);

  const fetchProtocols = async () => {
    try {
      setLoading(true);
      const data = await protocolService.getAllProtocols();
      setProtocols(data);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const createProtocol = async (protocolData) => {
    try {
      const newProtocol = await protocolService.createProtocol(protocolData);
      setProtocols([...protocols, newProtocol]);
      return newProtocol;
    } catch (err) {
      setError(err.message);
      throw err;
    }
  };

  const updateProtocol = async (id, updates) => {
    try {
      const updatedProtocol = await protocolService.updateProtocol(id, updates);
      setProtocols(protocols.map(p => 
        p.id === id ? updatedProtocol : p
      ));
      return updatedProtocol;
    } catch (err) {
      setError(err.message);
      throw err;
    }
  };

  const deleteProtocol = async (id) => {
    try {
      await protocolService.deleteProtocol(id);
      setProtocols(protocols.filter(p => p.id !== id));
    } catch (err) {
      setError(err.message);
      throw err;
    }
  };

  return {
    protocols,
    loading,
    error,
    createProtocol,
    updateProtocol,
    deleteProtocol,
    refreshProtocols: fetchProtocols
  };
};
