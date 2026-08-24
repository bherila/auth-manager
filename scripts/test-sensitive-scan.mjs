#!/usr/bin/env node

/* global process */

import { execFileSync } from 'node:child_process'
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'

const probeDirectory = 'client-data'
const probeFile = `${probeDirectory}/privacy-probe.json`
const contentProbeFile = 'sensitive-scan-probe.txt'
const syntheticCredential = ['sk', 'live', 'SyntheticValue1234567890'].join('_')
const syntheticEmail = ['billing', '@', 'customer', '.', 'com'].join('')
const syntheticContents = JSON.stringify({ syntheticCredential, syntheticEmail })

mkdirSync(probeDirectory, { recursive: true })
writeFileSync(probeFile, syntheticContents)
writeFileSync(contentProbeFile, syntheticContents)

try {
  execFileSync(process.execPath, ['scripts/scan-sensitive.mjs'], {
    encoding: 'utf8',
    stdio: 'pipe',
  })
  console.error('sensitive-scan test: expected the disclosure probe to fail')
  process.exitCode = 1
} catch (error) {
  const output = `${error.stdout ?? ''}${error.stderr ?? ''}`

  if (!output.includes('[private-data-file]')) {
    console.error('sensitive-scan test: private data path was not detected')
    process.exitCode = 1
  } else if (!output.includes('[stripe-live-credential]')) {
    console.error('sensitive-scan test: billing credential was not detected')
    process.exitCode = 1
  } else if (!output.includes('[non-test-email]')) {
    console.error('sensitive-scan test: client record was not detected')
    process.exitCode = 1
  } else if (output.includes(syntheticCredential) || output.includes(syntheticEmail)) {
    console.error('sensitive-scan test: finding output disclosed a matched value')
    process.exitCode = 1
  } else {
    console.log('sensitive-scan test: disclosure probe rejected with redacted output')
  }
} finally {
  rmSync(probeDirectory, { recursive: true, force: true })
  rmSync(contentProbeFile, { force: true })
}
