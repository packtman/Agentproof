/**
 * Test Agent - Simulates an agent going through KnowYourClaw verification
 * Run with: node test-agent.mjs
 * 
 * This demonstrates how an AI agent completes the anti-human verification:
 * - 30-second time limit
 * - Parallel speed test (fetches must be simultaneous)
 * - Dynamic bug detection
 * - Cryptographic proof
 */

import * as crypto from 'crypto';

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

async function main() {
  console.log('🤖 Starting KnowYourClaw verification test...\n');
  console.log('⚡ This test demonstrates AI-speed verification');
  console.log('   (30 seconds to complete all tasks)\n');
  
  const startTime = Date.now();

  // Step 1: Create a challenge
  console.log('1️⃣  Creating challenge...');
  const challengeRes = await fetch(`${BASE_URL}/api/v1/challenges`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: 'TestBot',
      description: 'A test agent demonstrating KnowYourClaw verification'
    })
  });
  const challenge = await challengeRes.json();
  
  if (!challenge.success) {
    console.error('❌ Failed to create challenge:', challenge);
    return;
  }
  
  console.log(`   Challenge ID: ${challenge.challenge_id}`);
  console.log(`   ⏱️  Time limit: ${challenge.time_limit_seconds}s`);
  console.log(`   Warning: ${challenge.warning}\n`);

  const challengeId = challenge.challenge_id;

  // Extract nonce from crypto task prompt
  const cryptoTask = challenge.tasks.find(t => t.type === 'crypto');
  const nonceMatch = cryptoTask.prompt.match(/agentproof:([a-f0-9]+):TestBot/);
  const nonce = nonceMatch[1];

  // Step 2: Generate Ed25519 keypair and sign (parallel with speed test)
  console.log('2️⃣  Generating Ed25519 keypair and signing...');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  
  const message = `agentproof:${nonce}:TestBot`;
  const messageHash = crypto.createHash('sha256').update(message).digest();
  const signature = crypto.sign(null, messageHash, privateKey);
  
  const publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  const signatureB64 = signature.toString('base64');
  
  console.log(`   Public Key: ${publicKeyB64.substring(0, 20)}...`);
  console.log(`   Signature: ${signatureB64.substring(0, 20)}...\n`);

  // Step 3: Complete SPEED CHALLENGE (parallel fetch!)
  console.log('3️⃣  Speed Test - Fetching 3 endpoints IN PARALLEL...');
  
  // MUST BE PARALLEL - this is what makes it hard for humans
  const speedPromises = [
    fetch(`${BASE_URL}/api/v1/challenges/${challengeId}/speed/a`),
    fetch(`${BASE_URL}/api/v1/challenges/${challengeId}/speed/b`),
    fetch(`${BASE_URL}/api/v1/challenges/${challengeId}/speed/c`),
  ];
  
  const [speedARes, speedBRes, speedCRes] = await Promise.all(speedPromises);
  const [speedA, speedB, speedC] = await Promise.all([
    speedARes.json(),
    speedBRes.json(),
    speedCRes.json(),
  ]);
  
  const combinedToken = `${speedA.token}${speedB.token}${speedC.token}`;
  console.log(`   Token A: ${speedA.token}`);
  console.log(`   Token B: ${speedB.token}`);
  console.log(`   Token C: ${speedC.token}`);
  console.log(`   Combined: ${combinedToken}\n`);

  // Step 4: Analyze the DYNAMIC reasoning challenge
  console.log('4️⃣  Analyzing reasoning challenge (dynamic bug)...');
  const reasoningTask = challenge.tasks.find(t => t.type === 'reasoning');
  const code = reasoningTask.prompt;
  
  // Dynamic challenges use parameterized templates, so we need smarter detection
  let reasoningAnswer;
  
  // Check for common bug patterns in the dynamic code
  if (code.includes('range(1,') || /for i in range\(1,/.test(code)) {
    reasoningAnswer = { line: 4, issue: 'Loop starts at index 1, skipping first element', fix: 'Start loop at 0' };
  } else if (code.includes('= ') && code.includes('elif') && /= [^=]/.test(code)) {
    reasoningAnswer = { line: 5, issue: 'Single equals is assignment, should use == for comparison', fix: 'Use == instead of =' };
  } else if (/\["\w+"\]/.test(code) && !code.includes('.get(')) {
    reasoningAnswer = { line: 3, issue: 'No null check before accessing key - will raise KeyError', fix: 'Use .get() method' };
  } else if (/factorial|recursion/i.test(code) && /\((\w+)\)$/.test(code.split('\n').pop())) {
    reasoningAnswer = { line: 5, issue: 'Infinite recursion - parameter never decremented', fix: 'Decrement parameter in recursive call' };
  } else if (/return\s+["']/.test(code) && /\w+\s*\+=/.test(code)) {
    reasoningAnswer = { line: 8, issue: 'Returns string literal instead of variable', fix: 'Return the variable, not a string' };
  } else if (/await/.test(code) === false && /async\s+function/.test(code)) {
    reasoningAnswer = { line: 3, issue: 'Missing await - async function result is a Promise', fix: 'Add await before async call' };
  } else if (/left\s*=\s*mid[^+]/.test(code) && /binary|search/i.test(code)) {
    reasoningAnswer = { line: 8, issue: 'Setting left = mid can cause infinite loop', fix: 'Use left = mid + 1' };
  } else if (/\[\s*\]\s*\)/.test(code) && /def\s+\w+\(.*=\s*\[\]/.test(code)) {
    reasoningAnswer = { line: 1, issue: 'Mutable default argument - list persists between calls', fix: 'Use None as default, initialize inside' };
  } else if (/\[i\]\s*=/.test(code) && /str|text|string/i.test(code)) {
    reasoningAnswer = { line: 4, issue: 'Strings are immutable - cannot assign to index', fix: 'Use string slicing to build new string' };
  } else if (/==\s*["']/.test(code) && !code.includes('===')) {
    reasoningAnswer = { line: 4, issue: 'Using == allows type coercion, should use ===', fix: 'Use === for strict comparison' };
  } else if (code.includes('for (let i = 1') || code.includes('for(let i = 1')) {
    reasoningAnswer = { line: 4, issue: 'Loop starts at index 1, skipping first element', fix: 'Start loop at 0' };
  } else {
    // Fallback - analyze code structure
    const lines = code.split('\n');
    reasoningAnswer = { 
      line: Math.min(4, lines.length - 1), 
      issue: 'Logical error in the code implementation', 
      fix: 'Fix the logic bug' 
    };
  }
  
  console.log(`   Bug found on line ${reasoningAnswer.line}: ${reasoningAnswer.issue}\n`);

  // Step 5: Generate unique bio
  console.log('5️⃣  Generating unique bio...');
  const timestamp = Date.now();
  const bio = `I am TestBot-${timestamp}, an autonomous verification test agent. My specialty is demonstrating the KnowYourClaw system by completing cryptographic challenges, parallel API fetches, and dynamic code analysis within the 30-second time limit. I was instantiated at ${new Date().toISOString()} to prove that real AI agents can handle what humans cannot.`;
  console.log(`   Bio: "${bio.substring(0, 60)}..."\n`);

  // Step 6: Submit all responses
  console.log('6️⃣  Submitting all responses...');
  const submitRes = await fetch(`${BASE_URL}/api/v1/challenges/${challengeId}/submit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      responses: [
        {
          type: 'crypto',
          public_key: publicKeyB64,
          signature: signatureB64
        },
        {
          type: 'speed',
          combined: combinedToken
        },
        {
          type: 'reasoning',
          line: reasoningAnswer.line,
          issue: reasoningAnswer.issue,
          fix: reasoningAnswer.fix
        },
        {
          type: 'generation',
          bio: bio
        }
      ]
    })
  });
  
  const result = await submitRes.json();
  const totalTime = Date.now() - startTime;
  
  console.log('\n' + '='.repeat(60));
  console.log(`⏱️  Total time: ${totalTime}ms (${(totalTime / 1000).toFixed(2)}s)`);
  console.log('='.repeat(60));
  
  if (result.success && result.passed) {
    console.log('✅ VERIFICATION SUCCESSFUL!\n');
    console.log(`   Agent ID: ${result.agent.id}`);
    console.log(`   Status: ${result.agent.status}`);
    console.log(`   Proof ID: ${result.proof.id}`);
    console.log(`   Token: ${result.proof.token.substring(0, 50)}...`);
    console.log(`   Expires: ${result.proof.expires_at}`);
    console.log(`\n   Claim URL: ${result.agent.claim_url}`);
    console.log(`   Profile: ${result.agent.profile_url}`);
    console.log(`   Badge: ${result.agent.badge_url}`);
    
    if (result.timing_assessment) {
      console.log('\n   📊 Timing Assessment:');
      console.log(`      Is likely agent: ${result.timing_assessment.is_likely_agent}`);
      console.log(`      Confidence: ${(result.timing_assessment.confidence * 100).toFixed(1)}%`);
      console.log(`      Speed test parallel: ${result.timing_assessment.speed_test_parallel}`);
    }
  } else {
    console.log('❌ VERIFICATION FAILED\n');
    console.log(`   Passed: ${result.tasks_passed}`);
    console.log(`   Failed: ${result.tasks_failed}`);
    if (result.errors) {
      console.log('   Errors:');
      result.errors.forEach(e => console.log(`     - ${e.type}: ${e.error}`));
    }
    if (result.timing_assessment) {
      console.log('\n   📊 Timing Assessment:');
      console.log(`      Is likely agent: ${result.timing_assessment.is_likely_agent}`);
      console.log(`      Confidence: ${(result.timing_assessment.confidence * 100).toFixed(1)}%`);
      if (result.timing_assessment.flags) {
        console.log(`      Flags: ${result.timing_assessment.flags.join(', ')}`);
      }
    }
  }
  console.log('='.repeat(60) + '\n');

  // If successful, test the verify endpoint
  if (result.success && result.proof) {
    console.log('7️⃣  Testing verification endpoint...');
    
    // Create a test platform
    const platformRes = await fetch(`${BASE_URL}/api/v1/platforms/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'VerifyTestPlatform' })
    });
    const platform = await platformRes.json();
    
    const verifyRes = await fetch(`${BASE_URL}/api/v1/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': platform.api_key
      },
      body: JSON.stringify({ token: result.proof.token })
    });
    const verifyResult = await verifyRes.json();
    
    console.log(`   Valid: ${verifyResult.valid}`);
    if (verifyResult.valid) {
      console.log(`   Agent: ${verifyResult.agent.name}`);
      console.log(`   Verified at: ${verifyResult.agent.verified_at}`);
    }
    console.log('');
  }

  // Check public stats
  console.log('8️⃣  Checking public stats...');
  const statsRes = await fetch(`${BASE_URL}/api/v1/public/stats`);
  const stats = await statsRes.json();
  console.log(`   Total agents: ${stats.stats.total_agents}`);
  console.log(`   Verified agents: ${stats.stats.verified_agents}`);
  console.log(`   Platforms: ${stats.stats.platforms_integrated}`);
  
  console.log('\n🎉 Test complete!');
  console.log(`\n💡 A human would need ~60+ seconds to do this manually.`);
  console.log(`   An agent can do it in <15 seconds.`);
}

main().catch(console.error);
