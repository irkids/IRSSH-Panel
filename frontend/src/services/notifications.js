import { Subject } from 'rxjs';

class NotificationService {
  constructor() {
    this.notifications = new Subject();
    this.socket = null;
  }

  connect() {
    this.socket = new WebSocket(process.env.REACT_APP_WS_URL);
    
    this.socket.onmessage = (event) => {
      const notification = JSON.parse(event.data);
      this.notifications.next(notification);
    };

    this.socket.onclose = () => {
      setTimeout(() => this.connect(), 5000);
    };
  }

  subscribe(callback) {
    return this.notifications.subscribe(callback);
  }

  send(notification) {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(notification));
    }
  }

  disconnect() {
    if (this.socket) {
      this.socket.close();
    }
  }
}

export const notificationService = new NotificationService();
