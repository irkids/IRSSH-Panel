# IRSSH-Panel

# IRSSH Panel

Advanced VPN Server Management Panel with multi-protocol support and real-time monitoring.

## Features

- **Multi-Protocol Support**
  - SSH
  - L2TP/IPSec
  - IKEv2
  - Cisco AnyConnect
  - WireGuard
  - SingBox (with Shadowsocks, TUIC, VLess, Hysteria2)

- **Real-Time Monitoring**
  - System resources
  - Network traffic
  - User connections
  - Protocol status
  - Geographical distribution

- **User Management**
  - User creation and management
  - Traffic quotas
  - Connection limits
  - Access control
  - Multi-protocol support per user

- **Security Features**
  - Two-factor authentication
  - Session management
  - IP restrictions
  - Automated backups
  - Audit logging

## Installation

### Quick Install

```bash
curl -sL https://raw.githubusercontent.com/username/IRSSH-Panel/main/scripts/install.sh | sudo bash
```

### Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/username/IRSSH-Panel.git
   cd IRSSH-Panel
   ```

2. Copy environment file:
   ```bash
   cp .env.example .env
   ```

3. Edit configuration:
   ```bash
   nano .env
   ```

4. Run installation script:
   ```bash
   sudo bash scripts/install.sh
   ```

## System Requirements

- Ubuntu 20.04 LTS or newer
- 2 CPU cores
- 2GB RAM minimum
- 20GB disk space
- PostgreSQL 12 or newer
- Python 3.8 or newer
- Node.js 16 or newer

## Development Setup

1. Backend Setup:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. Frontend Setup:
   ```bash
   cd frontend
   npm install
   ```

3. Start Development Servers:
   ```bash
   # Backend
   cd backend
   uvicorn app.main:app --reload

   # Frontend
   cd frontend
   npm start
   ```

## Documentation

- [API Documentation](docs/api.md)
- [User Guide](docs/user-guide.md)
- [Administrator Guide](docs/admin-guide.md)
- [Development Guide](docs/development.md)

## Security

For security issues, please email security@yourdomain.com instead of using the issue tracker.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- Documentation: [https://docs.yourpanel.com](https://docs.yourpanel.com)
- Issue Tracker: [GitHub Issues](https://github.com/username/IRSSH-Panel/issues)
- Community Forum: [https://forum.yourpanel.com](https://forum.yourpanel.com)

## Authors

- Main Developer - [Your Name](https://github.com/yourusername)

## Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Backend Framework
- [React](https://reactjs.org/) - Frontend Framework
- [Tailwind CSS](https://tailwindcss.com/) - CSS Framework
- [PostgreSQL](https://www.postgresql.org/) - Database
- All protocol authors and contributors

## Roadmap

- [ ] Add multi-server support
- [ ] Implement load balancing
- [ ] Add more protocols
- [ ] Enhance monitoring features
- [ ] Add mobile app
- [ ] Implement API rate limiting
- [ ] Add more payment gateways
- [ ] Enhance backup features

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for all changes.
