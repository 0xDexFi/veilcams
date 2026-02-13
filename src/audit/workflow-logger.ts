import fs from 'node:fs';
import path from 'node:path';
import type { ModuleName } from '../types/index.js';

/**
 * Human-readable unified workflow log.
 * Append-only, single file per session.
 */
export class WorkflowLogger {
  private filePath: string;

  constructor(outputDir: string) {
    this.filePath = path.join(outputDir, 'workflow.log');
  }

  async initialize(): Promise<void> {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const header = `=== VeilCams Workflow Log ===\nStarted: ${new Date().toISOString()}\n${'='.repeat(40)}\n\n`;
    fs.writeFileSync(this.filePath, header);
  }

  async logModule(moduleName: ModuleName, status: string, details?: Record<string, unknown>): Promise<void> {
    const timestamp = new Date().toISOString();
    let line = `[${timestamp}] [${moduleName.toUpperCase()}] ${status}`;
    if (details) {
      const detailStr = Object.entries(details)
        .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
        .join(' ');
      line += ` | ${detailStr}`;
    }
    line += '\n';
    fs.appendFileSync(this.filePath, line);
  }

  async logPhase(phase: string, status: string): Promise<void> {
    const timestamp = new Date().toISOString();
    const line = `\n[${timestamp}] --- PHASE: ${phase.toUpperCase()} ${status} ---\n`;
    fs.appendFileSync(this.filePath, line);
  }

  async logMessage(message: string): Promise<void> {
    const timestamp = new Date().toISOString();
    fs.appendFileSync(this.filePath, `[${timestamp}] ${message}\n`);
  }
}
