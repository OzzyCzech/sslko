# SSLko

[![NPM Downloads](https://img.shields.io/npm/dm/sslko?style=for-the-badge)](https://www.npmjs.com/package/sslko)
[![NPM Version](https://img.shields.io/npm/v/sslko?style=for-the-badge)](https://www.npmjs.com/package/sslko)
[![NPM License](https://img.shields.io/npm/l/sslko?style=for-the-badge)](https://github.com/OzzyCzech/sslko/blob/main/LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/OzzyCzech/sslko?style=for-the-badge)](https://github.com/OzzyCzech/sslko/commits/main)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/OzzyCzech/sslko/main.yml?style=for-the-badge)](https://github.com/OzzyCzech/sslko/actions)

**SSLko** is a lightweight JavaScript library for retrieving SSL/TLS certificate validity and expiration information.

## 📦 Installation

You can install SSLko using npm, yarn, pnpm, or bun:

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

## 🚀 Quick Start

### Get Certificate Information

```typescript
import { getCertificateInfo } from "sslko";

const certInfo = await getCertificateInfo("example.com");
console.log(certInfo);
```

Will return an [CertificateInfo](https://ozzyczech.github.io/sslko/interfaces/CertificateInfo.html) object.

### Get Certificate

```typescript
import { getCertificate } from 'sslko';
const cert = await getCertificate('example.com');
```

There is few options you can pass to the `getCertificate` function:

```typescript
import { getCertificate } from 'sslko';

const cert = await getCertificate('example.com', {
  port: 488, // Default is 443
  timeout: 10000, // Default is 5000ms => 5 seconds
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

--- 

Made with ❤️ by the [Roman Ožana](https://ozana.cz)   
