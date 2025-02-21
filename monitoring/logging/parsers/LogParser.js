class LogParser {
  parseLogLine(line) {
    try {
      const logPattern = /\[(?<timestamp>.*?)\]\s+(?<level>\w+)\s+(?<message>.*)/;
      const matches = line.match(logPattern);

      if (!matches) {
        throw new Error('Invalid log format');
      }

      const { timestamp, level, message } = matches.groups;

      return {
        timestamp: new Date(timestamp),
        level: level.toLowerCase(),
        message,
        metadata: this.extractMetadata(message)
      };
    } catch (error) {
      console.error('Error parsing log line:', error);
      return null;
    }
  }

  extractMetadata(message) {
    const metadata = {};
    
    // Extract IP addresses
    const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
    const ipMatch = message.match(ipPattern);
    if (ipMatch) {
      metadata.ip = ipMatch[0];
    }

    // Extract protocol information
    const protocolPattern = /protocol=(\w+)/;
    const protocolMatch = message.match(protocolPattern);
    if (protocolMatch) {
      metadata.protocol = protocolMatch[1];
    }

    // Extract user information
    const userPattern = /user=(\w+)/;
    const userMatch = message.match(userPattern);
    if (userMatch) {
      metadata.user = userMatch[1];
    }

    return metadata;
  }

  parseBatchLogs(logs) {
    return logs
      .split('\n')
      .map(line => this.parseLogLine(line))
      .filter(log => log !== null);
  }
}

module.exports = new LogParser();
