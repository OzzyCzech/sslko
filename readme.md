# 👾 SSLko

[![NPM Downloads](https://img.shields.io/npm/dm/sslko?style=for-the-badge)](https://www.npmjs.com/package/sslko)
[![NPM Version](https://img.shields.io/npm/v/sslko?style=for-the-badge)](https://www.npmjs.com/package/sslko)
[![NPM License](https://img.shields.io/npm/l/sslko?style=for-the-badge)](https://github.com/OzzyCzech/sslko/blob/main/LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/OzzyCzech/sslko?style=for-the-badge)](https://github.com/OzzyCzech/sslko/commits/main)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/OzzyCzech/sslko/main.yml?style=for-the-badge)](https://github.com/OzzyCzech/sslko/actions)

SSLko is a lightweight JavaScript library for retrieving SSL/TLS certificate validity and expiration information.

```bash
npm install sslko
```

```bash
yarn add sslko
```

```bash
pnpm add sslko
```

```bash
bun add sslko
```

### Basic Usage

```typescript
import { getCertificate } from 'sslko';

const cert = await getCertificate('example.com');
```

There is few options you can pass to the `getCertificate` function:

```typescript
import { getCertificate } from 'sslko';
const cert = await getCertificate('example.com', {
  port: 443, // Default is 443
  timeout: 5000, // Default is 10000ms
});
```

More information about the options can be found in the [API documentation](https://ozzyczech.github.io/sslko/).

## 📄 License

[MIT License](LICENSE) - see the [LICENSE](LICENSE) file for details.


## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
6. 
--- 

Made with ❤️ by the [Roman Ožana](https://ozana.cz)   
