import { createServer as createHttpServer } from 'http';
import path from 'path';
import fs from 'fs';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import expressModule from './backend/node_modules/express/index.js';
const express = expressModule.default || expressModule;

async function runMigrations() {
  try {
    console.log('Running database migrations...');
    execSync('npx sequelize-cli db:migrate', {
      cwd: path.join(__dirname, 'backend'),
      stdio: 'inherit',
    });
    console.log('Database migrations completed successfully.');

    if (process.env.IS_DEMO === 'true' || process.env.IS_DEMO === '1') {
      console.log('Demo mode: seeding the database with PIAP test cases...');
      try {
        execSync('npx sequelize-cli db:seed:all', {
          cwd: path.join(__dirname, 'backend'),
          stdio: 'inherit',
        });
        console.log('Database seeding completed successfully.');
      } catch (seedError) {
        // Seed data is already present (e.g. after a container restart with a
        // persistent volume). This is expected — log and continue.
        console.log('Seed data already present or seeding skipped — continuing startup.');
      }
    }
  } catch (error) {
    console.error('Error running database migrations:', error);
    throw error;
  }
}

async function startServer() {
  try {
    const server = express();
    const httpServer = createHttpServer(server);

    const backendAppModule = await import('./backend/server.js');
    const backendApp = backendAppModule.default || backendAppModule;
    server.use('/api', backendApp);

    const nextServerPath = './node_modules/next/dist/server/next.js';
    if (fs.existsSync(nextServerPath)) {
      const nextModule = await import(nextServerPath);
      const next = nextModule.default || nextModule;

      const dev = process.env.NODE_ENV !== 'production';
      const nextApp = next({ dev, dir: path.join(__dirname, '.') });
      const handle = nextApp.getRequestHandler();
      await nextApp.prepare();
      console.log('Next.js prepared');

      server.all('*', (req, res) => handle(req, res));
    } else {
      console.error('Next.js module not found at:', nextServerPath);
      server.all('*', (req, res) => {
        res.status(500).send('Frontend server not available');
      });
    }

    const PORT = process.env.PORT || 8000;
    httpServer.listen(PORT, (err) => {
      if (err) throw err;
      console.log(`> Ready on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('Error starting server:', error);
    process.exit(1);
  }
}

runMigrations()
  .then(() => {
    startServer();
  })
  .catch((error) => {
    console.error('Failed to start application:', error);
    process.exit(1);
  });
