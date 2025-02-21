const WebSocket = require('ws');
const config = require('../config/websocket');
const logger = require('./logger');

class WebSocketServer {
  constructor() {
    this.clients = new Map();
    this.server = null;
  }

  initialize(server) {
    this.server = new WebSocket.Server({
      server,
      path: config.path,
      maxPayload: 1024 * 1024 // 1MB
    });

    this.server.on('connection', this.handleConnection.bind(this));
    logger.info('WebSocket server initialized');
  }

  handleConnection(ws, req) {
    const clientId = req.headers['x-client-id'] || Math.random().toString(36).substr(2, 9);
    this.clients.set(clientId, ws);

    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('message', (message) => this.handleMessage(clientId, message));
    ws.on('close', () => this.handleDisconnection(clientId));
    ws.on('error', (error) => this.handleError(clientId, error));

    // Send initial state if needed
    this.sendToClient(clientId, {
      type: 'connection_established',
      data: { clientId }
    });

    logger.info(`Client connected: ${clientId}`);
  }

  handleMessage(clientId, message) {
    try {
      const data = JSON.parse(message);
      
      switch (data.type) {
        case 'ping':
          this.sendToClient(clientId, { type: 'pong' });
          break;
        case 'subscribe':
          this.handleSubscription(clientId, data.channels);
          break;
        default:
          this.handleCustomMessage(clientId, data);
      }
    } catch (error) {
      logger.error(`WebSocket message error: ${error.message}`, { clientId });
    }
  }

  handleDisconnection(clientId) {
    this.clients.delete(clientId);
    logger.info(`Client disconnected: ${clientId}`);
  }

  handleError(clientId, error) {
    logger.error(`WebSocket error: ${error.message}`, { clientId });
    this.clients.delete(clientId);
  }

  sendToClient(clientId, data) {
    const client = this.clients.get(clientId);
    if (client && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  }

  broadcast(data, filter = () => true) {
    this.clients.forEach((client, clientId) => {
      if (client.readyState === WebSocket.OPEN && filter(clientId)) {
        client.send(JSON.stringify(data));
      }
    });
  }

  handleCustomMessage(clientId, data) {
    // Handle custom message types
  }

  startHeartbeat() {
    setInterval(() => {
      this.clients.forEach((ws, clientId) => {
        if (ws.isAlive === false) {
          this.handleDisconnection(clientId);
          return ws.terminate();
        }
        
        ws.isAlive = false;
        ws.ping();
      });
    }, config.heartbeat.interval);
  }

  getConnectedClients() {
    return this.clients.size;
  }
}

module.exports = new WebSocketServer();
