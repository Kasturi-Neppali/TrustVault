#!/usr/bin/env node
/**
 * TrustVault - Admin Account Bootstrap Script
 * Securely seeds or provisions the initial System Administrator account
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const mongoose = require('mongoose');
const { User } = require('../models');
const { hashPassword, validatePassword } = require('../utils/password');
const { logAction } = require('../utils/audit');

async function seedAdmin() {
  console.log('=====================================================');
  console.log('    TRUSTVAULT SECURE ADMIN BOOTSTRAP PROVISIONER     ');
  console.log('=====================================================\n');

  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/trustvault';
  const email = (process.env.ADMIN_EMAIL || 'admin@trustvault.com').toLowerCase().trim();
  const password = process.env.ADMIN_PASSWORD || 'TrustVault@Admin2026!';
  const name = process.env.ADMIN_NAME || 'TrustVault Administrator';

  const passwordValidation = validatePassword(password);
  if (!passwordValidation.isValid) {
    console.error(`FATAL: Bootstrap admin password does not satisfy security policy: ${passwordValidation.error}`);
    process.exit(1);
  }

  try {
    await mongoose.connect(mongoUri, {
      runtimeAdapters: { os: require('os') }
    });
    console.log('Connected to MongoDB.');

    let adminUser = await User.findOne({ email });

    if (adminUser) {
      console.log(`Admin user with email "${email}" already exists (ID: ${adminUser._id}).`);
      if (adminUser.role !== 'admin') {
        adminUser.role = 'admin';
        await adminUser.save();
        console.log('Upgraded existing user to "admin" role.');
      }
      const newHash = await hashPassword(password);
      adminUser.passwordHash = newHash;
      adminUser.name = name;
      await adminUser.save();
      console.log('Admin password and profile updated successfully.');
    } else {
      const passwordHash = await hashPassword(password);
      adminUser = new User({
        name,
        email,
        passwordHash,
        role: 'admin'
      });
      await adminUser.save();
      console.log(`Successfully created bootstrap Administrator account:`);
      console.log(`  ID   : ${adminUser._id}`);
      console.log(`  Email: ${adminUser.email}`);
      console.log(`  Role : ${adminUser.role}`);
    }

    // Log the bootstrap event to the tamper-evident audit trail
    await logAction({
      actorId: adminUser._id,
      actorEmail: adminUser.email,
      action: 'admin_action',
      status: 'success',
      ipAddress: '127.0.0.1 (CLI bootstrap)',
      metadata: { description: 'Administrator bootstrap provisioning executed' }
    });

    console.log('\n[SUCCESS] Bootstrap admin is provisioned and logged in audit ledger.');
  } catch (err) {
    console.error('Error during admin provisioning:', err);
    process.exit(1);
  } finally {
    await mongoose.disconnect();
    console.log('Database disconnected.');
  }
}

if (require.main === module) {
  seedAdmin();
}

module.exports = { seedAdmin };

