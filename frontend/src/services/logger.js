class LoggerService {
  constructor() {
    this.levels = {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3
    };

    this.level = this.levels[process.env.REACT_APP_LOG_LEVEL || 'info'];
  }

  error(message, ...args) {
    if (this.level >= this.levels.error) {
      console.error(message, ...args);
    }
  }

  warn(message, ...args) {
    if (this.level >= this.levels.warn) {
      console.warn(message, ...args);
    }
  }

  info(message, ...args) {
    if (this.level >= this.levels.info) {
      console.info(message, ...args);
    }
  }

  debug(message, ...args) {
    if (this.level >= this.levels.debug) {
      console.debug(message, ...args);
    }
  }

  group(label) {
    console.group(label);
  }

  groupEnd() {
    console.groupEnd();
  }

  table(data) {
    console.table(data);
  }
}

export const logger = new LoggerService();
