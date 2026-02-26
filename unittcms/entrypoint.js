import { createServer as createHttpServer } from 'http';
import path from 'path';
import fs from 'fs';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// createRequire lets us call require() from within an ES module.
// Needed because bcrypt and sequelize v6 are CommonJS packages.
const _require = createRequire(import.meta.url);

import expressModule from './backend/node_modules/express/index.js';
const express = expressModule.default || expressModule;

async function seedDatabase() {
  try {
    const bcrypt = _require('/app/backend/node_modules/bcrypt');
    const { Sequelize } = _require('/app/backend/node_modules/sequelize');

    const sequelize = new Sequelize({
      dialect: 'sqlite',
      storage: path.join(__dirname, 'backend/data/database.sqlite'),
      logging: false,
    });

    const [[row]] = await sequelize.query('SELECT COUNT(*) as cnt FROM users');
    if (parseInt(row.cnt) > 0) {
      console.log('Users already exist — skipping seed.');
      await sequelize.close();
      return;
    }

    console.log('Seeding PIAP demo data...');

    // Discover actual column names so the INSERT matches the real schema.
    const [userCols] = await sequelize.query('PRAGMA table_info(users)');
    const colNames = userCols.map(c => c.name);
    console.log('[seed] users table columns:', colNames.join(', '));

    const hash = await bcrypt.hash('password', 10);
    const qi = sequelize.getQueryInterface();
    const now = new Date();

    const userRow = { email: 'admin@piap.local', password: hash, role: 0 };
    // Handle both 'username' and 'name' column naming conventions.
    if (colNames.includes('username'))    userRow.username    = 'Admin';
    if (colNames.includes('name'))        userRow.name        = 'Admin';
    if (colNames.includes('avatar_path')) userRow.avatar_path = null;
    // Handle both snake_case and camelCase timestamp conventions.
    if (colNames.includes('created_at'))  { userRow.created_at  = now; userRow.updated_at  = now; }
    if (colNames.includes('createdAt'))   { userRow.createdAt   = now; userRow.updatedAt   = now; }

    await qi.bulkInsert('users', [userRow]);

    await qi.bulkInsert('projects', [{
      name: 'Cisco Secure Access',
      detail: 'Test cases for validating Cisco Secure Access connectivity, internet access policies, and private access policies.',
      userId: 1,
      isPublic: true,
      createdAt: now,
      updatedAt: now,
    }]);

    await qi.bulkInsert('folders', [
      { name: 'Basic Connectivity',        detail: 'Verify that the Cisco Secure Access Roaming Client is active and routing traffic correctly.',                                                                             projectId: 1, createdAt: now, updatedAt: now },
      { name: 'Internet Access Policies',  detail: 'Validate each Internet Access security policy: Warn (Gen AI), Isolate (News), Block (Alcohol), Block (DeepSeek AI), and Allow All fallback.',                          projectId: 1, createdAt: now, updatedAt: now },
      { name: 'Private Access Policies',   detail: 'Validate the Private Access policy that grants ZTA-enrolled roaming devices access to all PoC in a Pod services.',                                                     projectId: 1, createdAt: now, updatedAt: now },
    ]);

    await qi.bulkInsert('cases', [
      { title: 'Verify browser traffic uses QUIC / HTTP3 via Secure Access',                 state: 1, priority: 2, type: 4, automationStatus: 1, template: 1, description: 'Confirms that Cisco Secure Access is forwarding traffic over QUIC (HTTP/3) for optimal performance and tunnel establishment.',                                                                                                                                                                          preConditions: 'Cisco Secure Access Roaming Client is installed, active, and connected on the test device.',                                                                                                                                                                                          expectedResults: "The http3.is page displays \"Yes, you're using HTTP/3 (QUIC)\", confirming that QUIC is active through Secure Access.",                                                                                                                                                            folderId: 1, createdAt: now, updatedAt: now },
      { title: 'Verify Cisco Secure Access policy is enforced on browser traffic',            state: 1, priority: 3, type: 4, automationStatus: 1, template: 1, description: "Confirms that the device's internet traffic is being inspected and enforced by a Cisco Secure Access policy, not bypassed.",                                                                                                                                                                            preConditions: 'Cisco Secure Access Roaming Client is installed and connected.',                                                                                                                                                                                                                      expectedResults: 'The policy test page at policy.test.sse.cisco.com confirms that a Cisco Secure Access policy is applied to this device\'s traffic.',                                                                                                                                               folderId: 1, createdAt: now, updatedAt: now },
      { title: 'Verify traffic exits through a Cisco Secure Access egress IP',               state: 1, priority: 2, type: 4, automationStatus: 1, template: 1, description: "Confirms that outbound traffic exits the internet through a Cisco Secure Access egress node, not through the local ISP's IP.",                                                                                                                                                                          preConditions: 'Cisco Secure Access Roaming Client is installed and connected.',                                                                                                                                                                                                                      expectedResults: "The IP shown on ifconfig.co belongs to Cisco Secure Access infrastructure and is not the local ISP's public IP address.",                                                                                                                                                          folderId: 1, createdAt: now, updatedAt: now },
      { title: 'Verify Cisco Secure Access tunnel has no significant packet loss',            state: 1, priority: 2, type: 4, automationStatus: 1, template: 1, description: 'Validates that the Cisco Secure Access tunnel is stable with minimal or zero packet loss under normal conditions.',                                                                                                                                                                                     preConditions: 'Cisco Secure Access Roaming Client is installed and connected.',                                                                                                                                                                                                                      expectedResults: 'Packet loss reported by packetlosstest.com is 0% or below 1%, confirming a stable and healthy tunnel.',                                                                                                                                                                            folderId: 1, createdAt: now, updatedAt: now },
      { title: 'Warn policy triggers when accessing Gen AI websites',                        state: 1, priority: 3, type: 2, automationStatus: 1, template: 1, description: 'Validates the Internet Access Warn policy for the Gen AI category. Policy: "joschwei - Roaming Devices - Warn - Page Gen AI Apps". SSL Decryption must be enabled in the Security Profile for the Warn page to render.',                                                                              preConditions: 'Roaming Client is active. Policy "joschwei - Roaming Devices - Warn - Page Gen AI Apps" is enabled in the CSA dashboard. SSL Decryption is enabled in the Security Profile.',                                                                                                        expectedResults: 'Cisco Secure Access Warn page is displayed before the Gen AI site loads, requiring the user to acknowledge and accept responsibility before proceeding.',                                                                                                                           folderId: 2, createdAt: now, updatedAt: now },
      { title: 'Browser Isolation is applied when accessing News websites',                  state: 1, priority: 3, type: 2, automationStatus: 1, template: 1, description: 'Validates the Browser Isolation policy for the News/Media category. Policy: "joschwei - Roaming Devices - Isolate - News Websites". SSL Decryption must be enabled in the Security Profile for isolation to function.',                                                                                preConditions: 'Roaming Client is active. Policy "joschwei - Roaming Devices - Isolate - News Websites" is enabled. SSL Decryption is enabled in the Security Profile.',                                                                                                                             expectedResults: 'The news website opens inside a Cisco Browser Isolation session. The page content renders in an isolated remote browser environment, protecting the endpoint from web-borne threats.',                                                                                               folderId: 2, createdAt: now, updatedAt: now },
      { title: 'Block policy prevents access to Alcohol category websites',                  state: 1, priority: 3, type: 2, automationStatus: 1, template: 1, description: 'Validates the Block policy for the Alcohol website category. Policy: "joschwei - Roaming Devices - Block - Alcohol Websites". SSL Decryption must be enabled for the block page to render correctly.',                                                                                                 preConditions: 'Roaming Client is active. Policy "joschwei - Roaming Devices - Block - Alcohol Websites" is enabled. SSL Decryption is enabled in the Security Profile.',                                                                                                                            expectedResults: 'Cisco Secure Access block page is displayed when attempting to access an alcohol-related website. Access is denied.',                                                                                                                                                               folderId: 2, createdAt: now, updatedAt: now },
      { title: 'DeepSeek AI is blocked by application-specific block policy',                state: 1, priority: 3, type: 2, automationStatus: 1, template: 1, description: 'Validates the application-level Block policy targeting DeepSeek AI by application ID. Policy: "joschwei - Roaming Devices - Block - DeepSeek AI". SSL Decryption must be enabled.',                                                                                                                   preConditions: 'Roaming Client is active. Policy "joschwei - Roaming Devices - Block - DeepSeek AI" is enabled. SSL Decryption is enabled in the Security Profile.',                                                                                                                                 expectedResults: 'Cisco Secure Access block page is displayed when navigating to deepseek.com or the DeepSeek AI application. Access is denied.',                                                                                                                                                     folderId: 2, createdAt: now, updatedAt: now },
      { title: 'Allow All fallback policy permits general internet access',                   state: 1, priority: 2, type: 2, automationStatus: 1, template: 1, description: 'Validates the catch-all Allow policy at lowest priority. Policy: "joschwei - Roaming Devices - Allow - All Internet".',                                                                                                                                                                                preConditions: 'Roaming Client is active. Policy "joschwei - Roaming Devices - Allow - All Internet" is enabled with the lowest rule priority. The destination URL does not match any higher-priority block, warn, or isolate policy.',                                                               expectedResults: 'The website loads successfully with no Secure Access block or warn page. Traffic is routed and decrypted through Secure Access transparently.',                                                                                                                                     folderId: 2, createdAt: now, updatedAt: now },
      { title: 'ZTA-enrolled devices can reach all PoC in a Pod services via Private Access', state: 1, priority: 3, type: 2, automationStatus: 1, template: 1, description: 'Validates the Private Access policy that grants ZTA-enrolled roaming devices access to all 9 PIAP services without a traditional VPN. Policy: "Roaming User - PoC in a Pod Apps".',                                                                                                                 preConditions: 'Device is ZTA-enrolled. Roaming Client is active. Policy "Roaming User - PoC in a Pod Apps" is enabled in the CSA dashboard. Cisco Resource Connector is running in the k3s cluster. Test is performed from a remote network.',                                                     expectedResults: 'All 9 PoC in a Pod services are reachable from the remote device without a traditional VPN client. Traffic is transparently proxied through Cisco Secure Access Private Access.',                                                                                                  folderId: 3, createdAt: now, updatedAt: now },
    ]);

    await qi.bulkInsert('steps', [
      { step: 'Open a browser on the test device.',                                                                                                                 result: 'Browser opens without errors.',                                                                  createdAt: now, updatedAt: now }, // 1
      { step: 'Navigate to https://http3.is/',                                                                                                                      result: 'Page loads and displays the QUIC/HTTP3 detection result.',                                       createdAt: now, updatedAt: now }, // 2
      { step: 'Open a browser on the test device.',                                                                                                                 result: 'Browser opens without errors.',                                                                  createdAt: now, updatedAt: now }, // 3
      { step: 'Navigate to https://policy.test.sse.cisco.com/',                                                                                                    result: 'Page loads and displays Cisco Secure Access policy information for this device.',                 createdAt: now, updatedAt: now }, // 4
      { step: 'Open a browser on the test device.',                                                                                                                 result: 'Browser opens without errors.',                                                                  createdAt: now, updatedAt: now }, // 5
      { step: 'Navigate to https://ifconfig.co/',                                                                                                                   result: 'Page displays the current public egress IP address.',                                            createdAt: now, updatedAt: now }, // 6
      { step: "Cross-reference the displayed IP against known Cisco Secure Access egress IP ranges, or verify it does not match your local ISP's assigned IP.",    result: 'IP is confirmed as a Cisco Secure Access egress IP, not the local ISP IP.',                     createdAt: now, updatedAt: now }, // 7
      { step: 'Open a browser on the test device.',                                                                                                                 result: 'Browser opens without errors.',                                                                  createdAt: now, updatedAt: now }, // 8
      { step: 'Navigate to https://packetlosstest.com/',                                                                                                            result: 'Packet loss test page loads.',                                                                   createdAt: now, updatedAt: now }, // 9
      { step: 'Click the Start button and wait for the test to complete.',                                                                                          result: 'Test completes and displays the packet loss percentage.',                                         createdAt: now, updatedAt: now }, // 10
      { step: 'Open a browser on the test device.',                                                                                                                 result: 'Browser opens without errors.',                                                                  createdAt: now, updatedAt: now }, // 11
      { step: 'Navigate to a Gen AI website, e.g. chat.openai.com or gemini.google.com.',                                                                          result: 'Cisco Secure Access intercepts the request before the page loads.',                              createdAt: now, updatedAt: now }, // 12
      { step: 'Observe the browser response and check whether a Warn page is shown.',                                                                               result: 'A Cisco Secure Access Warn page is displayed. The user can choose to proceed or go back.',      createdAt: now, updatedAt: now }, // 13
      { step: 'Open a browser on the test device.',                                                                                                                 result: 'Browser opens without errors.',                                                                  createdAt: now, updatedAt: now }, // 14
      { step: 'Navigate to a news website, e.g. bbc.com or cnn.com.',                                                                                              result: 'Cisco Secure Access intercepts the request.',                                                    createdAt: now, updatedAt: now }, // 15
      { step: 'Observe how the page loads and note any browser isolation indicators.',                                                                              result: 'The page opens inside a Cisco Browser Isolation session.',                                        createdAt: now, updatedAt: now }, // 16
      { step: 'Open a browser on the test device.',                                                                                                                 result: 'Browser opens without errors.',                                                                  createdAt: now, updatedAt: now }, // 17
      { step: 'Navigate to an alcohol-related website, e.g. wine.com or totalwine.com.',                                                                           result: 'Cisco Secure Access intercepts the request.',                                                    createdAt: now, updatedAt: now }, // 18
      { step: 'Observe the browser response.',                                                                                                                      result: 'Cisco Secure Access block page is displayed. The site does not load.',                           createdAt: now, updatedAt: now }, // 19
      { step: 'Open a browser on the test device.',                                                                                                                 result: 'Browser opens without errors.',                                                                  createdAt: now, updatedAt: now }, // 20
      { step: 'Navigate to deepseek.com.',                                                                                                                          result: 'Cisco Secure Access intercepts the request.',                                                    createdAt: now, updatedAt: now }, // 21
      { step: 'Observe the browser response.',                                                                                                                      result: 'Cisco Secure Access block page is displayed specifically for DeepSeek AI.',                      createdAt: now, updatedAt: now }, // 22
      { step: 'Open a browser on the test device.',                                                                                                                 result: 'Browser opens without errors.',                                                                  createdAt: now, updatedAt: now }, // 23
      { step: 'Navigate to a legitimate general website, e.g. cisco.com or example.com.',                                                                          result: 'Cisco Secure Access routes the traffic using the Allow All fallback policy.',                    createdAt: now, updatedAt: now }, // 24
      { step: 'Verify the website loads completely and no block or warn page is shown.',                                                                            result: 'Website loads successfully. No Secure Access intervention page is shown.',                       createdAt: now, updatedAt: now }, // 25
      { step: 'Connect the test device to a remote network that has no direct route to the PoC VM.',                                                                result: 'Device is on a remote network with the Roaming Client active and connected.',                    createdAt: now, updatedAt: now }, // 26
      { step: 'Open a browser and navigate to the Dashy Overview on port 30100.',                                                                                  result: 'Dashy dashboard loads successfully.',                                                            createdAt: now, updatedAt: now }, // 27
      { step: 'Navigate to the Automagic Server on port 30200.',                                                                                                   result: 'Automagic Server UI loads successfully.',                                                        createdAt: now, updatedAt: now }, // 28
      { step: 'Navigate to the UnitTCMS Test Guide on port 30350.',                                                                                                result: 'UnitTCMS loads successfully.',                                                                   createdAt: now, updatedAt: now }, // 29
      { step: 'Initiate an SSH connection to the OpenSSH Server on port 30022.',                                                                                   result: 'SSH session is established successfully.',                                                       createdAt: now, updatedAt: now }, // 30
      { step: 'Navigate to the Web Server on port 30400.',                                                                                                         result: 'Web Server page loads successfully.',                                                            createdAt: now, updatedAt: now }, // 31
      { step: 'Navigate to the Splunk Dashboard on port 30500.',                                                                                                   result: 'Splunk Dashboard loads and the login page or home screen is displayed.',                         createdAt: now, updatedAt: now }, // 32
      { step: 'Access the Splunk MCP endpoint on port 30501.',                                                                                                     result: 'Splunk MCP endpoint responds successfully.',                                                     createdAt: now, updatedAt: now }, // 33
      { step: 'Initiate an RDP connection to the RDP Server on port 30390.',                                                                                       result: 'RDP session is established and the remote desktop is displayed.',                                createdAt: now, updatedAt: now }, // 34
      { step: 'Access the Kubectl MCP Server on port 30050.',                                                                                                      result: 'Kubectl MCP Server responds successfully.',                                                      createdAt: now, updatedAt: now }, // 35
    ]);

    await qi.bulkInsert('caseSteps', [
      { caseId:  1, stepId:  1, stepNo:  1, createdAt: now, updatedAt: now },
      { caseId:  1, stepId:  2, stepNo:  2, createdAt: now, updatedAt: now },
      { caseId:  2, stepId:  3, stepNo:  1, createdAt: now, updatedAt: now },
      { caseId:  2, stepId:  4, stepNo:  2, createdAt: now, updatedAt: now },
      { caseId:  3, stepId:  5, stepNo:  1, createdAt: now, updatedAt: now },
      { caseId:  3, stepId:  6, stepNo:  2, createdAt: now, updatedAt: now },
      { caseId:  3, stepId:  7, stepNo:  3, createdAt: now, updatedAt: now },
      { caseId:  4, stepId:  8, stepNo:  1, createdAt: now, updatedAt: now },
      { caseId:  4, stepId:  9, stepNo:  2, createdAt: now, updatedAt: now },
      { caseId:  4, stepId: 10, stepNo:  3, createdAt: now, updatedAt: now },
      { caseId:  5, stepId: 11, stepNo:  1, createdAt: now, updatedAt: now },
      { caseId:  5, stepId: 12, stepNo:  2, createdAt: now, updatedAt: now },
      { caseId:  5, stepId: 13, stepNo:  3, createdAt: now, updatedAt: now },
      { caseId:  6, stepId: 14, stepNo:  1, createdAt: now, updatedAt: now },
      { caseId:  6, stepId: 15, stepNo:  2, createdAt: now, updatedAt: now },
      { caseId:  6, stepId: 16, stepNo:  3, createdAt: now, updatedAt: now },
      { caseId:  7, stepId: 17, stepNo:  1, createdAt: now, updatedAt: now },
      { caseId:  7, stepId: 18, stepNo:  2, createdAt: now, updatedAt: now },
      { caseId:  7, stepId: 19, stepNo:  3, createdAt: now, updatedAt: now },
      { caseId:  8, stepId: 20, stepNo:  1, createdAt: now, updatedAt: now },
      { caseId:  8, stepId: 21, stepNo:  2, createdAt: now, updatedAt: now },
      { caseId:  8, stepId: 22, stepNo:  3, createdAt: now, updatedAt: now },
      { caseId:  9, stepId: 23, stepNo:  1, createdAt: now, updatedAt: now },
      { caseId:  9, stepId: 24, stepNo:  2, createdAt: now, updatedAt: now },
      { caseId:  9, stepId: 25, stepNo:  3, createdAt: now, updatedAt: now },
      { caseId: 10, stepId: 26, stepNo:  1, createdAt: now, updatedAt: now },
      { caseId: 10, stepId: 27, stepNo:  2, createdAt: now, updatedAt: now },
      { caseId: 10, stepId: 28, stepNo:  3, createdAt: now, updatedAt: now },
      { caseId: 10, stepId: 29, stepNo:  4, createdAt: now, updatedAt: now },
      { caseId: 10, stepId: 30, stepNo:  5, createdAt: now, updatedAt: now },
      { caseId: 10, stepId: 31, stepNo:  6, createdAt: now, updatedAt: now },
      { caseId: 10, stepId: 32, stepNo:  7, createdAt: now, updatedAt: now },
      { caseId: 10, stepId: 33, stepNo:  8, createdAt: now, updatedAt: now },
      { caseId: 10, stepId: 34, stepNo:  9, createdAt: now, updatedAt: now },
      { caseId: 10, stepId: 35, stepNo: 10, createdAt: now, updatedAt: now },
    ]);

    await qi.bulkInsert('members', [
      { projectId: 1, userId: 1, role: 0, createdAt: now, updatedAt: now },
    ]);

    await sequelize.close();
    console.log('Seed complete. Login: admin@piap.local / password');
  } catch (e) {
    console.error('Seeding failed:', e.message);
    console.error(e.stack);
    // Non-fatal — app continues even if seed fails
  }
}

async function runMigrations() {
  try {
    console.log('Running database migrations...');
    execSync('npx sequelize-cli db:migrate', {
      cwd: path.join(__dirname, 'backend'),
      stdio: 'inherit',
    });
    console.log('Database migrations completed successfully.');

    // Sequelize-cli may write the DB to the backend root rather than data/.
    // Move it into the PVC-mounted location so the app and seed agree on the path.
    const targetDb = path.join(__dirname, 'backend/data/database.sqlite');
    const rootDb   = path.join(__dirname, 'backend/database.sqlite');
    if (!fs.existsSync(targetDb) && fs.existsSync(rootDb)) {
      console.log(`[db] Moving database to PVC: ${rootDb} → ${targetDb}`);
      fs.mkdirSync(path.dirname(targetDb), { recursive: true });
      fs.renameSync(rootDb, targetDb);
    }

    await seedDatabase();
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
