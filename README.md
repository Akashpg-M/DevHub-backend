# Authentication System

A complete authentication system built with Node.js, Express, TypeScript, and PostgreSQL. Supports both JWT-based authentication and OAuth 2.0 (Google and GitHub).

## Features

DeveloperHub: Community-Driven Collaborative Platform for Developers
📌 Project Summary
DeveloperHub is a feature-rich, full-stack web application designed to empower developers by offering an all-in-one platform for collaboration, communication, project management, and knowledge sharing. The platform supports a hierarchical, community-based structure, facilitating everything from public Q&A to version-controlled code editing, video meetings, and task management—all within secure and scalable developer communities.
________________________________________
🧩 Core Functionalities
1. 🏘️ Community System
•	Create / Join Communities
•	Community Visibility Modes:
o	Public: Open to all users
o	Protected Public: Join requests require admin approval
o	Private: Hidden from listings; joinable only via invite link
•	Hierarchical Roles & Permissions:
o	Customizable role hierarchy (e.g., Owner > Admin > Maintainer > Member)
o	Role-based access to community features and communication channels
________________________________________
2. 👥 Subgroup System
•	Communities can create subgroups (e.g., “Frontend Team”, “Infra Team”)
•	Each subgroup has its own:
o	Dedicated chat
o	Task management panel
o	Video meeting room
o	Collaborative code editor
________________________________________
3. 💬 Chat System
•	Real-time messaging with Socket.IO
•	1-on-1 and group chats
•	Role-based Council Chat:
o	Only top members of each level can communicate in preceding higher-level channels
o	Enables structured discussion between subgroup leads, managers, and admins
________________________________________
4. ✅ Task & Project Management
•	Kanban-style task boards for each subgroup
•	Task assignment to individuals or entire groups
•	Tasks support:
o	Title, Description, Priority, Deadline, Comments
o	Status tracking: Todo → In Progress → Done
________________________________________
5. 🧑‍💻 Git-Based Collaborative Code Editor
•	Real-time collaboration using Monaco Editor + Yjs/Liveblocks
•	Key Features:
o	Version control system with branching support
o	Multiplayer editing with cursor presence and inline comments
o	Export code or sync with external GitHub repositories (optional future feature)
________________________________________
6. 🎥 Virtual Meeting Rooms
•	Built with WebRTC or third-party SDKs like Daily or Jitsi
•	Each community or subgroup can host:
o	Instant video calls
o	Scheduled meetings
o	Screen sharing & chat sidebar
________________________________________
7. 🌐 Public Developer Conversations
•	Q&A-style public discussion forum similar to Stack Overflow
•	Tag-based navigation
•	Voting and accepted answers to foster high-quality contributions
•	Moderation tools for community leads
________________________________________
🎯 Vision
To provide a unified, scalable, and intuitive platform that encourages developer collaboration, fosters community-led learning, and supports real-world software workflows like version control, task assignment, and structured team communication.

- JWT-based authentication with access and refresh tokens
- OAuth 2.0 integration with Google and GitHub
- Password hashing with bcrypt
- PostgreSQL database with TypeORM
- TypeScript support
- Input validation
- Error handling
- Token refresh mechanism
- Protected routes

## Prerequisites

- Node.js (v14 or higher)
- PostgreSQL
- Google OAuth 2.0 credentials
- GitHub OAuth credentials

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory with the following variables:
```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=your_password
DB_NAME=developer_hub

# JWT Configuration
JWT_ACCESS_SECRET=your_access_token_secret
JWT_REFRESH_SECRET=your_refresh_token_secret
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# OAuth Configuration
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GITHUB_CALLBACK_URL=http://localhost:3000/auth/github/callback
```

4. Build the project:
```bash
npm run build
```

5. Start the server:
```bash
npm start
```

For development with hot-reload:
```bash
npm run dev
```

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login with email and password
- `POST /api/auth/logout` - Logout user
- `POST /api/auth/refresh-token` - Get new access token using refresh token

### Request/Response Examples

#### Register
```json
POST /api/auth/register
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "fullName": "John Doe",
  "username": "johndoe"
}
```

#### Login
```json
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

## Security Features

- Password hashing using bcrypt
- JWT token-based authentication
- Refresh token rotation
- Input validation and sanitization
- CORS protection
- Helmet security headers
- Rate limiting (coming soon)

## Development

### Project Structure
```
src/
├── controllers/     # Route controllers
├── middleware/      # Custom middleware
├── models/         # Database models
├── routes/         # API routes
├── services/       # Business logic
└── index.ts        # Application entry point
```

### Adding New Features

1. Create necessary models in `src/models/`
2. Add business logic in `src/services/`
3. Create controllers in `src/controllers/`
4. Define routes in `src/routes/`
5. Add validation middleware if needed

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.