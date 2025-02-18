// /opt/irssh-panel/backend/src/utils/ProtocolManager.js
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const logger = require('./logger');

class ProtocolManager {
    constructor() {
        this.configPath = '/etc/enhanced_ssh/config.yaml';
        this.protocols = {};
        this.initializeProtocols();
    }

    async initializeProtocols() {
        try {
            const config = yaml.load(fs.readFileSync(this.configPath, 'utf8'));
            this.protocols = config.protocols;

            for (const [name, protocol] of Object.entries(this.protocols)) {
                if (protocol.enabled) {
                    await this.verifyProtocol(name, protocol);
                }
            }
        } catch (error) {
            logger.error(`Failed to initialize protocols: ${error.message}`);
            throw error;
        }
    }

    async verifyProtocol(name, protocol) {
        const scriptPath = path.join('/opt/irssh-panel/modules/protocols', protocol.script);
        if (!fs.existsSync(scriptPath)) {
            throw new Error(`Protocol script not found: ${scriptPath}`);
        }

        try {
            const result = await this.executeScript(name, 'verify');
            logger.info(`Protocol ${name} verified: ${result}`);
        } catch (error) {
            logger.error(`Protocol ${name} verification failed: ${error.message}`);
            throw error;
        }
    }

    async executeScript(protocol, action, params = {}) {
        return new Promise((resolve, reject) => {
            const scriptPath = path.join('/opt/irssh-panel/modules/protocols', this.protocols[protocol].script);
            const process = spawn(scriptPath, [action, JSON.stringify(params)]);
            
            let output = '';
            let error = '';

            process.stdout.on('data', (data) => {
                output += data.toString();
            });

            process.stderr.on('data', (data) => {
                error += data.toString();
            });

            process.on('close', (code) => {
                if (code !== 0) {
                    reject(new Error(`Script execution failed: ${error}`));
                    return;
                }
                try {
                    resolve(JSON.parse(output));
                } catch {
                    resolve(output);
                }
            });
        });
    }

    async createAccount(protocol, userData) {
        if (!this.protocols[protocol]?.enabled) {
            throw new Error(`Protocol ${protocol} is not enabled`);
        }

        try {
            const result = await this.executeScript(protocol, 'create', userData);
            logger.info(`Created ${protocol} account for user ${userData.username}`);
            return result;
        } catch (error) {
            logger.error(`Failed to create ${protocol} account: ${error.message}`);
            throw error;
        }
    }

    async deleteAccount(protocol, userData) {
        if (!this.protocols[protocol]?.enabled) {
            throw new Error(`Protocol ${protocol} is not enabled`);
        }

        try {
            const result = await this.executeScript(protocol, 'delete', userData);
            logger.info(`Deleted ${protocol} account for user ${userData.username}`);
            return result;
        } catch (error) {
            logger.error(`Failed to delete ${protocol} account: ${error.message}`);
            throw error;
        }
    }

    async getStatus(protocol, userData) {
        if (!this.protocols[protocol]?.enabled) {
            throw new Error(`Protocol ${protocol} is not enabled`);
        }

        try {
            const result = await this.executeScript(protocol, 'status', userData);
            return result;
        } catch (error) {
            logger.error(`Failed to get ${protocol} status: ${error.message}`);
            throw error;
        }
    }

    async updateAccount(protocol, userData) {
        if (!this.protocols[protocol]?.enabled) {
            throw new Error(`Protocol ${protocol} is not enabled`);
        }

        try {
            const result = await this.executeScript(protocol, 'update', userData);
            logger.info(`Updated ${protocol} account for user ${userData.username}`);
            return result;
        } catch (error) {
            logger.error(`Failed to update ${protocol} account: ${error.message}`);
            throw error;
        }
    }
}

module.exports = new ProtocolManager();
