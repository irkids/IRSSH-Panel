import { useEffect, useRef, useCallback } from 'react';

export const useWebSocket = (url, options = {}) => {
  const ws = useRef(null);
  const {
    onOpen,
    onMessage,
    onClose,
    onError,
    reconnectAttempts = 5,
    reconnectInterval = 3000,
    autoReconnect = true
  } = options;

  const connect = useCallback(() => {
    ws.current = new WebSocket(url);

    ws.current.onopen = (event) => {
      console.log('WebSocket connected');
      if (onOpen) onOpen(event);
    };

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (onMessage) onMessage(data);
    };

    ws.current.onclose = (event) => {
      console.log('WebSocket disconnected');
      if (onClose) onClose(event);
      if (autoReconnect) {
        setTimeout(() => {
          if (reconnectAttempts > 0) {
            connect();
            reconnectAttempts--;
          }
        }, reconnectInterval);
      }
    };

    ws.current.onerror = (error) => {
      console.error('WebSocket error:', error);
      if (onError) onError(error);
    };
  }, [url, onOpen, onMessage, onClose, onError, reconnectAttempts, reconnectInterval, autoReconnect]);

  const disconnect = useCallback(() => {
    if (ws.current) {
      ws.current.close();
    }
  }, []);

  const send = useCallback((data) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(data));
    } else {
      console.warn('WebSocket is not connected');
    }
  }, []);

  useEffect(() => {
    connect();
    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  return {
    send,
    disconnect,
    connect,
    isConnected: ws.current?.readyState === WebSocket.OPEN
  };
};
