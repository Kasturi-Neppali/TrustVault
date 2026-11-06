#!/usr/bin/env node
/**
 * TrustVault - Cryptographic Audit Chain Verification Script
 * Validates the full audit trail ledger against tamper-evidence requirements
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const mongoose = require('mongoose');
const { AuditLog } = require('../models');
const { verifyAuditChain } = require('../utils/auditIntegrity');

async function run() {
  console.log('=====================================================');
  console.log('   TRUSTVAULT CRYPTOGRAPHIC AUDIT VERIFICATION TOOL   ');
  console.log('=====================================================\n');

  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/trustvault';
  console.log(`Connecting to database: ${mongoUri.replace(/:[^:]*@/, ':****@')}`);

  try {
    await mongoose.connect(mongoUri, {
      runtimeAdapters: { os: require('os') }
    });
    console.log('Connected to MongoDB.\nAnalyzing audit log records...');

    const result = await verifyAuditChain(AuditLog);

    if (result.isValid) {
      console.log('\n[PASS] AUDIT INTEGRITY STATUS: VALID');
      console.log(`Total Audit Records Inspected: ${result.totalRecords}`);
      console.log(`Verified Continuous Records : ${result.verifiedRecords}`);
      console.log(`Latest Cryptographic Hash  : ${result.latestHash}`);
      console.log('\nAll audit events maintain an unbroken SHA-256 hash chain.');
      console.log('No deletion, insertion, or in-place tampering detected.');
      process.exitCode = 0;
    } else {
      console.error('\n[FAIL] CRITICAL TAMPER DETECTED IN AUDIT LEDGER!');
      console.error(`Reason                : ${result.reason}`);
      console.error(`Tampered Record Index : ${result.tamperedIndex}`);
      console.error(`Database Record ID    : ${result.recordId}`);
      console.error(`Event ID              : ${result.eventId}`);
      if (result.expectedPreviousHash) {
        console.error(`Expected Prev Hash    : ${result.expectedPreviousHash}`);
        console.error(`Found Prev Hash       : ${result.actualPreviousHash}`);
      }
      if (result.expectedHash) {
        console.error(`Expected Entry Hash   : ${result.expectedHash}`);
        console.error(`Found Entry Hash      : ${result.storedHash}`);
      }
      process.exitCode = 1;
    }
  } catch (err) {
    console.error('Audit verification execution error:', err);
    process.exitCode = 2;
  } finally {
    await mongoose.disconnect();
    console.log('\nVerification run finished.');
  }
}

if (require.main === module) {
  run();
}

module.exports = { run };

