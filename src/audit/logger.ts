import fs from 'node:fs';
import path from 'node:path';
import type { ModuleName, AuditEvent } from '../types/index.js';

/**
 * Append-only JSONL logger for per-module execution logs.
 * Crash-safe: each line is a complete JSON object flushed immediately.
 */
export class ModuleLogger {
  private filePath: string;
  private fd: number | null = null;
  private moduleName: ModuleName;

  constructor(outputDir: string, moduleName: ModuleName, attempt: number) {
    const agentsDir = path.join(outputDir, 'agents');
    fs.mkdirSync(agentsDir, { recursive: true });
    this.filePath = path.join(agentsDir, `${moduleName}_attempt_${attempt}.jsonl`);
    this.moduleName = moduleName;
  }

  open(): void {
    this.fd = fs.openSync(this.filePath, 'a');
  }

  async logEvent(event: string, data: Record<string, unknown>): Promise<void> {
    const entry: AuditEvent = {
      timestamp: new Date().toISOString(),
      module: this.moduleName,
      event,
      data,
    };

    const line = JSON.stringify(entry) + '\n';

    if (this.fd !== null) {
      fs.writeSync(this.fd, line);
      fs.fsyncSync(this.fd);
    } else {
      fs.appendFileSync(this.filePath, line);
    }
  }

  close(): void {
    if (this.fd !== null) {
      fs.closeSync(this.fd);
      this.fd = null;
    }
  }
}
