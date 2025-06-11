# Express Application

A basic Express.js application with a simple API setup.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file in the root directory (optional):
```bash
PORT=3000
```

## Running the Application

Development mode (with auto-reload):
```bash
npm run dev
```

Production mode:
```bash
npm start
```

The server will start on port 3000 by default (or the port specified in your .env file).

## Available Endpoints

- `GET /`: Welcome message
- `GET /health`: Health check endpoint

## Features

- Express.js server
- CORS enabled
- JSON body parsing
- Error handling middleware
- Environment variable support
- Development mode with auto-reload (nodemon) 