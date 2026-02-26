# Auth Portal — 統一認證入口

A shared authentication system for Daniel's education apps.

## Features

- 📝 User registration with security questions (Traditional Chinese UI)
- 🔐 JWT-based authentication
- 🔑 Password recovery via security questions
- ⚙️ API Key management (OpenAI-compatible keys)
- 🔗 Cross-app authentication flow with redirect support
- 🌐 CORS enabled for all origins (Vercel cross-domain)

## Tech Stack

- **Backend:** Express.js
- **Database:** Turso (libSQL)
- **Auth:** bcryptjs + jsonwebtoken
- **Hosting:** Vercel

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/register` | No | Create account |
| POST | `/api/login` | No | Login, returns JWT (supports `?redirect=`) |
| POST | `/api/forgot-password/verify` | No | Get security question |
| POST | `/api/forgot-password/reset` | No | Reset password |
| GET | `/api/me` | Yes | Get current user |
| GET | `/api/verify-token` | Yes | Verify token (for other apps) |
| GET | `/api/settings` | Yes | Get API settings |
| POST | `/api/settings/api-key` | Yes | Save API key |
| DELETE | `/api/settings/api-key` | Yes | Clear API key |
| POST | `/api/settings/test-key` | Yes | Test API connection |

## Cross-App Auth Flow

1. App checks `localStorage` for JWT token
2. No token → redirect to `AUTH_PORTAL_URL/?redirect=CURRENT_APP_URL`
3. User logs in at auth portal
4. Auth portal redirects to `REDIRECT_URL?token=JWT_TOKEN`
5. App reads token from URL, stores in localStorage, strips from URL

## Setup

### Environment Variables

```bash
TURSO_DATABASE_URL=libsql://your-db.turso.io
TURSO_AUTH_TOKEN=your-auth-token
JWT_SECRET=your-secret-key
PORT=3000  # optional, defaults to 3000
```

### Local Development

```bash
npm install
npm start
```

### Deploy to Vercel

1. Push to GitHub
2. Import in Vercel
3. Add environment variables (TURSO_DATABASE_URL, TURSO_AUTH_TOKEN, JWT_SECRET)
4. Deploy

## Integration

Copy `auth-client.js` to your app and update `AUTH_PORTAL_URL`:

```js
const AUTH_PORTAL_URL = 'https://your-auth-portal.vercel.app';
```

See `auth-client.js` for full usage instructions.
