import { closeSync, mkdirSync, openSync } from 'node:fs';
import { resolve } from 'node:path';

if (process.platform === 'darwin') {
  try {
    const nodeModulesPath = resolve('node_modules');

    mkdirSync(nodeModulesPath, { recursive: true });
    closeSync(openSync(resolve(nodeModulesPath, '.metadata_never_index'), 'w'));
  } catch (error) {
    console.warn(`Unable to create node_modules/.metadata_never_index: ${error.message}`);
  }
}
