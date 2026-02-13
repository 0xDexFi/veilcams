import fs from 'node:fs';
import path from 'node:path';
import type { ModuleName, SessionMetrics } from '../types/index.js';
import { ModuleLogger } from './logger.js';
import { WorkflowLogger } from './workflow-logger.js';
import { MetricsTracker } from './metrics-tracker.js';
import { SessionMutex } from '../utils/concurrency.js';

export interface AuditSessionOptions {
  sessionId: string;
  outputDir: string;
}

/**
 * Facade coordinating all audit subsystems.
 * Thread-safe via SessionMutex for parallel module execution.
 */
export class AuditSession {
  private sessionId: string;
  private outputDir: string;
  private metricsTracker: MetricsTracker;
  private workflowLogger: WorkflowLogger;
  private currentLogger: ModuleLogger | null = null;
  private mutex: SessionMutex;

  constructor(options: AuditSessionOptions) {
    this.sessionId = options.sessionId;
    this.outputDir = options.outputDir;
    this.metricsTracker = new MetricsTracker(options.outputDir, options.sessionId);
    this.workflowLogger = new WorkflowLogger(options.outputDir);
    this.mutex = new SessionMutex(options.outputDir);
  }

  async initialize(): Promise<void> {
    fs.mkdirSync(this.outputDir, { recursive: true });
    fs.mkdirSync(path.join(this.outputDir, 'agents'), { recursive: true });
    fs.mkdirSync(path.join(this.outputDir, 'deliverables'), { recursive: true });

    await this.metricsTracker.initialize();
    await this.workflowLogger.initialize();
  }

  async startModule(moduleName: ModuleName, attempt: number): Promise<void> {
    this.currentLogger = new ModuleLogger(this.outputDir, moduleName, attempt);
    this.currentLogger.open();

    const unlock = await this.mutex.lock(this.sessionId);
    try {
      await this.metricsTracker.reload();
      this.metricsTracker.startModule(moduleName, attempt);
    } finally {
      unlock();
    }

    await this.workflowLogger.logModule(moduleName, 'STARTED', { attempt });
    await this.currentLogger.logEvent('module_start', { moduleName, attempt });
  }

  async endModule(moduleName: ModuleName, success: boolean, error?: string): Promise<void> {
    if (this.currentLogger) {
      await this.currentLogger.logEvent('module_end', { moduleName, success, error });
      this.currentLogger.close();
      this.currentLogger = null;
    }

    const unlock = await this.mutex.lock(this.sessionId);
    try {
      await this.metricsTracker.reload();
      this.metricsTracker.endModule(moduleName, success, error);
    } finally {
      unlock();
    }

    await this.workflowLogger.logModule(
      moduleName,
      success ? 'COMPLETED' : 'FAILED',
      error ? { error } : undefined
    );
  }

  async skipModule(moduleName: ModuleName): Promise<void> {
    const unlock = await this.mutex.lock(this.sessionId);
    try {
      await this.metricsTracker.reload();
      this.metricsTracker.skipModule(moduleName);
    } finally {
      unlock();
    }
    await this.workflowLogger.logModule(moduleName, 'SKIPPED');
  }

  async logEvent(event: string, data: Record<string, unknown>): Promise<void> {
    if (this.currentLogger) {
      await this.currentLogger.logEvent(event, data);
    }
  }

  async logPhase(phase: string, status: string): Promise<void> {
    await this.workflowLogger.logPhase(phase, status);
  }

  async logMessage(message: string): Promise<void> {
    await this.workflowLogger.logMessage(message);
  }

  async finalize(summary: SessionMetrics['summary']): Promise<void> {
    const unlock = await this.mutex.lock(this.sessionId);
    try {
      await this.metricsTracker.reload();
      this.metricsTracker.finalize(summary);
    } finally {
      unlock();
    }
    await this.workflowLogger.logMessage('=== Workflow completed ===');
  }

  async markFailed(error: string): Promise<void> {
    const unlock = await this.mutex.lock(this.sessionId);
    try {
      await this.metricsTracker.reload();
      this.metricsTracker.markFailed(error);
    } finally {
      unlock();
    }
    await this.workflowLogger.logMessage(`=== Workflow FAILED: ${error} ===`);
  }

  saveDeliverable(filename: string, content: string): string {
    const filePath = path.join(this.outputDir, 'deliverables', filename);
    fs.writeFileSync(filePath, content);
    return filePath;
  }

  getMetrics(): SessionMetrics {
    return this.metricsTracker.getMetrics();
  }
}
