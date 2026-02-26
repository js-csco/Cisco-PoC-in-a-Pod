import bcrypt from 'bcrypt';

export default {
  async up(queryInterface, Sequelize) {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash('password', saltRounds);

    // -----------------------------------------------------------------------
    // Users
    // -----------------------------------------------------------------------
    await queryInterface.bulkInsert('users', [
      {
        email: 'admin@piap.local',
        password: hashedPassword,
        username: 'Admin',
        role: 0,
        avatar_path: null,
        created_at: new Date(),
        updated_at: new Date(),
      },
    ]);

    // -----------------------------------------------------------------------
    // Projects
    // -----------------------------------------------------------------------
    await queryInterface.bulkInsert('projects', [
      {
        name: 'Cisco Secure Access',
        detail:
          'Test cases for validating Cisco Secure Access connectivity, internet access policies, and private access policies.',
        userId: 1,
        isPublic: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ]);

    // -----------------------------------------------------------------------
    // Folders  (projectId: 1)
    // ID 1 - Basic Connectivity
    // ID 2 - Internet Access Policies
    // ID 3 - Private Access Policies
    // -----------------------------------------------------------------------
    await queryInterface.bulkInsert('folders', [
      {
        name: 'Basic Connectivity',
        detail: 'Verify that the Cisco Secure Access Roaming Client is active and routing traffic correctly.',
        projectId: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        name: 'Internet Access Policies',
        detail:
          'Validate each Internet Access security policy: Warn (Gen AI), Isolate (News), Block (Alcohol), Block (DeepSeek AI), and Allow All fallback.',
        projectId: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        name: 'Private Access Policies',
        detail:
          'Validate the Private Access policy that grants ZTA-enrolled roaming devices access to all PoC in a Pod services.',
        projectId: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ]);

    // -----------------------------------------------------------------------
    // Cases
    // Folder 1 - Basic Connectivity    → caseId 1-4
    // Folder 2 - Internet Access       → caseId 5-9
    // Folder 3 - Private Access        → caseId 10
    // -----------------------------------------------------------------------
    await queryInterface.bulkInsert('cases', [

      // ---- Basic Connectivity (folderId: 1) --------------------------------
      {
        title: 'Verify browser traffic uses QUIC / HTTP3 via Secure Access',
        state: 1, priority: 2, type: 4, automationStatus: 1, template: 1,
        description: 'Confirms that Cisco Secure Access is forwarding traffic over QUIC (HTTP/3) for optimal performance and tunnel establishment.',
        preConditions: 'Cisco Secure Access Roaming Client is installed, active, and connected on the test device.',
        expectedResults: "The http3.is page displays \"Yes, you're using HTTP/3 (QUIC)\", confirming that QUIC is active through Secure Access.",
        folderId: 1, createdAt: new Date(), updatedAt: new Date(),
      },
      {
        title: 'Verify Cisco Secure Access policy is enforced on browser traffic',
        state: 1, priority: 3, type: 4, automationStatus: 1, template: 1,
        description: "Confirms that the device's internet traffic is being inspected and enforced by a Cisco Secure Access policy, not bypassed.",
        preConditions: 'Cisco Secure Access Roaming Client is installed and connected.',
        expectedResults: "The policy test page at policy.test.sse.cisco.com confirms that a Cisco Secure Access policy is applied to this device's traffic.",
        folderId: 1, createdAt: new Date(), updatedAt: new Date(),
      },
      {
        title: 'Verify traffic exits through a Cisco Secure Access egress IP',
        state: 1, priority: 2, type: 4, automationStatus: 1, template: 1,
        description: "Confirms that outbound traffic exits the internet through a Cisco Secure Access egress node, not through the local ISP's IP.",
        preConditions: 'Cisco Secure Access Roaming Client is installed and connected.',
        expectedResults: "The IP shown on ifconfig.co belongs to Cisco Secure Access infrastructure and is not the local ISP's public IP address.",
        folderId: 1, createdAt: new Date(), updatedAt: new Date(),
      },
      {
        title: 'Verify Cisco Secure Access tunnel has no significant packet loss',
        state: 1, priority: 2, type: 4, automationStatus: 1, template: 1,
        description: 'Validates that the Cisco Secure Access tunnel is stable with minimal or zero packet loss under normal conditions.',
        preConditions: 'Cisco Secure Access Roaming Client is installed and connected.',
        expectedResults: 'Packet loss reported by packetlosstest.com is 0% or below 1%, confirming a stable and healthy tunnel.',
        folderId: 1, createdAt: new Date(), updatedAt: new Date(),
      },

      // ---- Internet Access Policies (folderId: 2) --------------------------
      {
        title: 'Warn policy triggers when accessing Gen AI websites',
        state: 1, priority: 3, type: 2, automationStatus: 1, template: 1,
        description: 'Validates the Internet Access Warn policy for the Gen AI category. Policy: "joschwei - Roaming Devices - Warn - Page Gen AI Apps". SSL Decryption must be enabled in the Security Profile for the Warn page to render.',
        preConditions: 'Roaming Client is active. Policy "joschwei - Roaming Devices - Warn - Page Gen AI Apps" is enabled in the CSA dashboard. SSL Decryption is enabled in the Security Profile.',
        expectedResults: 'Cisco Secure Access Warn page is displayed before the Gen AI site loads, requiring the user to acknowledge and accept responsibility before proceeding.',
        folderId: 2, createdAt: new Date(), updatedAt: new Date(),
      },
      {
        title: 'Browser Isolation is applied when accessing News websites',
        state: 1, priority: 3, type: 2, automationStatus: 1, template: 1,
        description: 'Validates the Browser Isolation policy for the News/Media category. Policy: "joschwei - Roaming Devices - Isolate - News Websites". SSL Decryption must be enabled in the Security Profile for isolation to function.',
        preConditions: 'Roaming Client is active. Policy "joschwei - Roaming Devices - Isolate - News Websites" is enabled. SSL Decryption is enabled in the Security Profile.',
        expectedResults: 'The news website opens inside a Cisco Browser Isolation session. The page content renders in an isolated remote browser environment, protecting the endpoint from web-borne threats.',
        folderId: 2, createdAt: new Date(), updatedAt: new Date(),
      },
      {
        title: 'Block policy prevents access to Alcohol category websites',
        state: 1, priority: 3, type: 2, automationStatus: 1, template: 1,
        description: 'Validates the Block policy for the Alcohol website category. Policy: "joschwei - Roaming Devices - Block - Alcohol Websites". SSL Decryption must be enabled for the block page to render correctly.',
        preConditions: 'Roaming Client is active. Policy "joschwei - Roaming Devices - Block - Alcohol Websites" is enabled. SSL Decryption is enabled in the Security Profile.',
        expectedResults: 'Cisco Secure Access block page is displayed when attempting to access an alcohol-related website. Access is denied.',
        folderId: 2, createdAt: new Date(), updatedAt: new Date(),
      },
      {
        title: 'DeepSeek AI is blocked by application-specific block policy',
        state: 1, priority: 3, type: 2, automationStatus: 1, template: 1,
        description: 'Validates the application-level Block policy targeting DeepSeek AI by application ID. Policy: "joschwei - Roaming Devices - Block - DeepSeek AI". SSL Decryption must be enabled.',
        preConditions: 'Roaming Client is active. Policy "joschwei - Roaming Devices - Block - DeepSeek AI" is enabled. SSL Decryption is enabled in the Security Profile.',
        expectedResults: 'Cisco Secure Access block page is displayed when navigating to deepseek.com or the DeepSeek AI application. Access is denied.',
        folderId: 2, createdAt: new Date(), updatedAt: new Date(),
      },
      {
        title: 'Allow All fallback policy permits general internet access',
        state: 1, priority: 2, type: 2, automationStatus: 1, template: 1,
        description: 'Validates the catch-all Allow policy at lowest priority, ensuring general internet traffic is permitted when no higher-priority block/warn/isolate policy matches. Policy: "joschwei - Roaming Devices - Allow - All Internet".',
        preConditions: 'Roaming Client is active. Policy "joschwei - Roaming Devices - Allow - All Internet" is enabled with the lowest rule priority. The destination URL does not match any higher-priority block, warn, or isolate policy.',
        expectedResults: 'The website loads successfully with no Secure Access block or warn page. Traffic is routed and decrypted through Secure Access transparently.',
        folderId: 2, createdAt: new Date(), updatedAt: new Date(),
      },

      // ---- Private Access Policies (folderId: 3) ---------------------------
      {
        title: 'ZTA-enrolled devices can reach all PoC in a Pod services via Private Access',
        state: 1, priority: 3, type: 2, automationStatus: 1, template: 1,
        description: 'Validates the Private Access policy that grants ZTA-enrolled roaming devices access to all 9 PIAP services without a traditional VPN. Policy: "Roaming User - PoC in a Pod Apps". The Cisco Resource Connector must be running in the k3s cluster.',
        preConditions: 'Device is ZTA-enrolled. Roaming Client is active. Policy "Roaming User - PoC in a Pod Apps" is enabled in the CSA dashboard. Cisco Resource Connector is running and registered in the k3s cluster. Test is performed from a remote network (not on the same local network as the PoC VM).',
        expectedResults: 'All 9 PoC in a Pod services are reachable from the remote device without a traditional VPN client. Traffic is transparently proxied through Cisco Secure Access Private Access.',
        folderId: 3, createdAt: new Date(), updatedAt: new Date(),
      },
    ]);

    // -----------------------------------------------------------------------
    // Steps
    // -----------------------------------------------------------------------
    await queryInterface.bulkInsert('steps', [
      // Case 1 (stepIds 1-2)
      { step: 'Open a browser on the test device.', result: 'Browser opens without errors.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to https://http3.is/', result: 'Page loads and displays the QUIC/HTTP3 detection result.', createdAt: new Date(), updatedAt: new Date() },
      // Case 2 (stepIds 3-4)
      { step: 'Open a browser on the test device.', result: 'Browser opens without errors.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to https://policy.test.sse.cisco.com/', result: 'Page loads and displays Cisco Secure Access policy information for this device.', createdAt: new Date(), updatedAt: new Date() },
      // Case 3 (stepIds 5-7)
      { step: 'Open a browser on the test device.', result: 'Browser opens without errors.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to https://ifconfig.co/', result: 'Page displays the current public egress IP address.', createdAt: new Date(), updatedAt: new Date() },
      { step: "Cross-reference the displayed IP against known Cisco Secure Access egress IP ranges, or verify it does not match your local ISP's assigned IP.", result: 'IP is confirmed as a Cisco Secure Access egress IP, not the local ISP IP.', createdAt: new Date(), updatedAt: new Date() },
      // Case 4 (stepIds 8-10)
      { step: 'Open a browser on the test device.', result: 'Browser opens without errors.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to https://packetlosstest.com/', result: 'Packet loss test page loads.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Click the Start button and wait for the test to complete.', result: 'Test completes and displays the packet loss percentage.', createdAt: new Date(), updatedAt: new Date() },
      // Case 5 (stepIds 11-13)
      { step: 'Open a browser on the test device.', result: 'Browser opens without errors.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to a Gen AI website, e.g. chat.openai.com or gemini.google.com.', result: 'Cisco Secure Access intercepts the request before the page loads.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Observe the browser response and check whether a Warn page is shown.', result: 'A Cisco Secure Access Warn page is displayed. The user can choose to proceed or go back.', createdAt: new Date(), updatedAt: new Date() },
      // Case 6 (stepIds 14-16)
      { step: 'Open a browser on the test device.', result: 'Browser opens without errors.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to a news website, e.g. bbc.com or cnn.com.', result: 'Cisco Secure Access intercepts the request.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Observe how the page loads and note any browser isolation indicators.', result: 'The page opens inside a Cisco Browser Isolation session. The toolbar or page border may indicate isolated mode.', createdAt: new Date(), updatedAt: new Date() },
      // Case 7 (stepIds 17-19)
      { step: 'Open a browser on the test device.', result: 'Browser opens without errors.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to an alcohol-related website, e.g. wine.com or totalwine.com.', result: 'Cisco Secure Access intercepts the request.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Observe the browser response.', result: 'Cisco Secure Access block page is displayed. The site does not load.', createdAt: new Date(), updatedAt: new Date() },
      // Case 8 (stepIds 20-22)
      { step: 'Open a browser on the test device.', result: 'Browser opens without errors.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to deepseek.com.', result: 'Cisco Secure Access intercepts the request.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Observe the browser response.', result: 'Cisco Secure Access block page is displayed specifically for DeepSeek AI. The application does not load.', createdAt: new Date(), updatedAt: new Date() },
      // Case 9 (stepIds 23-25)
      { step: 'Open a browser on the test device.', result: 'Browser opens without errors.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to a legitimate general website, e.g. cisco.com or example.com.', result: 'Cisco Secure Access routes the traffic using the Allow All fallback policy.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Verify the website loads completely and no block or warn page is shown.', result: 'Website loads successfully. No Secure Access intervention page is shown.', createdAt: new Date(), updatedAt: new Date() },
      // Case 10 (stepIds 26-35)
      { step: 'Connect the test device to a remote network that has no direct route to the PoC VM.', result: 'Device is on a remote network with the Roaming Client active and connected.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Open a browser and navigate to the Dashy Overview on port 30100.', result: 'Dashy dashboard loads successfully.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to the Automagic Server on port 30200.', result: 'Automagic Server UI loads successfully.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to the UnitTCMS Test Guide on port 30350.', result: 'UnitTCMS loads successfully.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Initiate an SSH connection to the OpenSSH Server on port 30022.', result: 'SSH session is established successfully.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to the Web Server on port 30400.', result: 'Web Server page loads successfully.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Navigate to the Splunk Dashboard on port 30500.', result: 'Splunk Dashboard loads and the login page or home screen is displayed.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Access the Splunk MCP endpoint on port 30501.', result: 'Splunk MCP endpoint responds successfully.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Initiate an RDP connection to the RDP Server on port 30390.', result: 'RDP session is established and the remote desktop is displayed.', createdAt: new Date(), updatedAt: new Date() },
      { step: 'Access the Kubectl MCP Server on port 30050.', result: 'Kubectl MCP Server responds successfully.', createdAt: new Date(), updatedAt: new Date() },
    ]);

    // -----------------------------------------------------------------------
    // CaseSteps
    // -----------------------------------------------------------------------
    await queryInterface.bulkInsert('caseSteps', [
      { caseId: 1, stepId:  1, stepNo: 1, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 1, stepId:  2, stepNo: 2, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 2, stepId:  3, stepNo: 1, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 2, stepId:  4, stepNo: 2, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 3, stepId:  5, stepNo: 1, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 3, stepId:  6, stepNo: 2, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 3, stepId:  7, stepNo: 3, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 4, stepId:  8, stepNo: 1, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 4, stepId:  9, stepNo: 2, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 4, stepId: 10, stepNo: 3, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 5, stepId: 11, stepNo: 1, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 5, stepId: 12, stepNo: 2, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 5, stepId: 13, stepNo: 3, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 6, stepId: 14, stepNo: 1, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 6, stepId: 15, stepNo: 2, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 6, stepId: 16, stepNo: 3, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 7, stepId: 17, stepNo: 1, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 7, stepId: 18, stepNo: 2, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 7, stepId: 19, stepNo: 3, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 8, stepId: 20, stepNo: 1, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 8, stepId: 21, stepNo: 2, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 8, stepId: 22, stepNo: 3, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 9, stepId: 23, stepNo: 1, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 9, stepId: 24, stepNo: 2, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 9, stepId: 25, stepNo: 3, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 10, stepId: 26, stepNo:  1, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 10, stepId: 27, stepNo:  2, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 10, stepId: 28, stepNo:  3, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 10, stepId: 29, stepNo:  4, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 10, stepId: 30, stepNo:  5, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 10, stepId: 31, stepNo:  6, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 10, stepId: 32, stepNo:  7, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 10, stepId: 33, stepNo:  8, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 10, stepId: 34, stepNo:  9, createdAt: new Date(), updatedAt: new Date() },
      { caseId: 10, stepId: 35, stepNo: 10, createdAt: new Date(), updatedAt: new Date() },
    ]);

    // -----------------------------------------------------------------------
    // Members
    // -----------------------------------------------------------------------
    await queryInterface.bulkInsert('members', [
      { projectId: 1, userId: 1, role: 0, createdAt: new Date(), updatedAt: new Date() },
    ]);
  },

  async down(queryInterface, Sequelize) {
    // no-op
  },
};
