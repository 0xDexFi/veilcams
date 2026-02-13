import fs from 'node:fs';
import path from 'node:path';
import type { ModuleName, ModuleMetrics, SessionMetrics } from '../types/index.js';
import { MODULE_PHASE_MAP } from '../constants.js';

/**
 * Tracks session metrics with atomic writes to session.json.
 * Must be used with SessionMutex for concurrent access safety.
 */
export class MetricsTracker {
  private filePath: string;
  private metrics: SessionMetrics;

  constructor(outputDir: string, sessionId: string) {
    this.filePath = path.join(outputDir, 'session.json');
    this.metrics = {
      sessionId,
      startTime: new Date().toISOString(),
      status: 'running',
      config: {},
      modules: {} as Record<ModuleName, ModuleMetrics>,
    };
  }

  async initialize(): Promise<void> {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    await this.flush();
  }

  async reload(): Promise<void> {
    if (fs.existsSync(this.filePath)) {
      const content = fs.readFileSync(this.filePath, 'utf-8');
      this.metrics = JSON.parse(content);
    }
  }

  startModule(moduleName: ModuleName, attempt: number): void {
    this.metrics.modules[moduleName] = {
      name: moduleName,
      phase: MODULE_PHASE_MAP[moduleName],
      status: 'running',
      startTime: new Date().toISOString(),
      attempt,
    };
    this.flushSync();
  }

  endModule(moduleName: ModuleName, success: boolean, error?: string): void {
    const mod = this.metrics.modules[moduleName];
    if (!mod) return;

    mod.status = success ? 'completed' : 'failed';
    mod.endTime = new Date().toISOString();
    mod.durationMs = new Date(mod.endTime).getTime() - new Date(mod.startTime!).getTime();
    if (error) mod.error = error;

    this.flushSync();
  }

  skipModule(moduleName: ModuleName): void {
    this.metrics.modules[moduleName] = {
      name: moduleName,
      phase: MODULE_PHASE_MAP[moduleName],
      status: 'skipped',
      attempt: 0,
    };
    this.flushSync();
  }

  finalize(summary: SessionMetrics['summary']): void {
    this.metrics.status = 'completed';
    this.metrics.endTime = new Date().toISOString();
    this.metrics.totalDurationMs = new Date(this.metrics.endTime).getTime() - new Date(this.metrics.startTime).getTime();
    this.metrics.summary = summary;
    this.flushSync();
  }

  markFailed(error: string): void {
    this.metrics.status = 'failed';
    this.metrics.error = error;
    this.metrics.endTime = new Date().toISOString();
    this.metrics.totalDurationMs = new Date(this.metrics.endTime).getTime() - new Date(this.metrics.startTime).getTime();
    this.flushSync();
  }

  getMetrics(): SessionMetrics {
    return structuredClone(this.metrics);
  }

  private async flush(): Promise<void> {
    this.flushSync();
  }

  /** Atomic write: write to tmp then rename (with Windows NTFS fallback) */
  private flushSync(): void {
    const tmpPath = this.filePath + '.tmp';
    fs.writeFileSync(tmpPath, JSON.stringify(this.metrics, null, 2));
    try {
      fs.renameSync(tmpPath, this.filePath);
    } catch {
      // On Windows NTFS, rename can fail if target is held open. Fallback to copy + delete.
      fs.copyFileSync(tmpPath, this.filePath);
      fs.unlinkSync(tmpPath);
    }
  }
}
