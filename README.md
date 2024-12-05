# Forge Development Environment Manager

A comprehensive, secure development environment management tool built in Rust.

## Features

- Secure environment management with encryption
- Multi-factor authentication support
- Cloud provider integration (AWS)
- Geolocation-based access control
- Advanced security features
- Email notifications
- Audit logging
- Recovery code system

## Prerequisites

- Rust 1.70 or higher
- PostgreSQL 13 or higher
- Redis 6 or higher
- SMTP server access for email notifications

## Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/forge-dev-env-manager.git
cd forge-dev-env-manager
```

2. Copy the environment template:
```bash
cp .env.template .env
```

3. Edit the `.env` file with your configuration:
- Database credentials
- AWS credentials (if using cloud features)
- SMTP settings
- Security keys
- Other configuration options

4. Create the database:
```bash
createdb forge_db
```

5. Build the project:
```bash
cargo build --release
```

## Running the Application

1. Start the application:
```bash
./target/release/dev-env-manager
```

2. Create an admin user:
```bash
./target/release/dev-env-manager user create --username admin --role administrator
```

## Security Best Practices

1. Always use strong passwords and keep them secure
2. Enable MFA for administrative accounts
3. Regularly rotate security keys
4. Monitor audit logs
5. Keep the application and dependencies updated
6. Use HTTPS in production
7. Follow the principle of least privilege

## Configuration

The application uses a layered configuration system:

1. Default configuration (`config/default.toml`)
2. Environment-specific configuration (`config/{environment}.toml`)
3. Local configuration (`config/local.toml`)
4. Environment variables
5. Command line arguments

## Environment Variables

See `.env.template` for all available environment variables and their descriptions.

## Development

1. Install development dependencies:
```bash
cargo install --path .
```

2. Run tests:
```bash
cargo test
```

3. Run with development configuration:
```bash
cargo run
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.
