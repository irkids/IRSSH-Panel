import React, { createContext, useContext, useReducer } from 'react';

const MetricsContext = createContext();

const initialState = {
  metrics: {},
  filters: {
    timeRange: '1h',
    type: 'all'
  },
  settings: {
    refreshInterval: 5000,
    alertThresholds: {
      cpu: 80,
      memory: 85,
      disk: 90
    }
  }
};

const metricsReducer = (state, action) => {
  switch (action.type) {
    case 'UPDATE_METRICS':
      return { ...state, metrics: { ...state.metrics, ...action.payload } };
    case 'UPDATE_FILTERS':
      return { ...state, filters: { ...state.filters, ...action.payload } };
    case 'UPDATE_SETTINGS':
      return { ...state, settings: { ...state.settings, ...action.payload } };
    default:
      return state;
  }
};

export const MetricsProvider = ({ children }) => {
  const [state, dispatch] = useReducer(metricsReducer, initialState);

  return (
    <MetricsContext.Provider value={{ state, dispatch }}>
      {children}
    </MetricsContext.Provider>
  );
};

export const useMetricsContext = () => {
  const context = useContext(MetricsContext);
  if (!context) {
    throw new Error('useMetricsContext must be used within a MetricsProvider');
  }
  return context;
};
