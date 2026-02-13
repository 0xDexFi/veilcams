/**
 * File-based mutex for crash-safe concurrent access to session.json.
 * Mirrors Shannon's SessionMutex pattern.
 */

import fs from 'node:fs';
import path from 'node:path';

export class SessionMutex {
  private lockDir: string;
  private retryIntervalMs = 50;
  private maxWaitMs = 10_000;

  constructor(baseDir: string) {
    this.lockDir = path.join(baseDir, '.session-lock');
  }

  async lock(sessionId: string): Promise<() => void> {
    const lockFile = path.join(this.lockDir, `${sessionId}.lock`);
    const start = Date.now();

    while (true) {
      try {
        fs.mkdirSync(path.dirname(lockFile), { recursive: true });
        fs.writeFileSync(lockFile, String(process.pid), { flag: 'wx' });
        return () => this.unlock(lockFile);
      } catch (err: unknown) {
        const error = err as NodeJS.ErrnoException;
        if (error.code !== 'EEXIST') throw error;

        if (Date.now() - start > this.maxWaitMs) {
          // Stale lock — force acquire
          try { fs.unlinkSync(lockFile); } catch { /* noop */ }
          continue;
        }

        await new Promise((resolve) => setTimeout(resolve, this.retryIntervalMs));
      }
    }
  }

  private unlock(lockFile: string): void {
    try { fs.unlinkSync(lockFile); } catch { /* already cleaned */ }
  }
}

/**
 * Rate limiter using token bucket algorithm.
 */
export class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private readonly maxTokens: number;
  private readonly refillRate: number;

  constructor(requestsPerSecond: number) {
    this.maxTokens = requestsPerSecond;
    this.tokens = requestsPerSecond;
    this.refillRate = requestsPerSecond;
    this.lastRefill = Date.now();
  }

  async acquire(): Promise<void> {
    this.refill();
    while (this.tokens < 1) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      this.refill();
    }
    this.tokens -= 1;
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.maxTokens, this.tokens + elapsed * this.refillRate);
    this.lastRefill = now;
  }
}

/**
 * Execute promises with concurrency limit.
 */
export async function parallelLimit<T>(
  tasks: (() => Promise<T>)[],
  concurrency: number
): Promise<PromiseSettledResult<T>[]> {
  const results: PromiseSettledResult<T>[] = new Array(tasks.length);
  let index = 0;

  async function worker(): Promise<void> {
    while (index < tasks.length) {
      const currentIndex = index++;
      try {
        const value = await tasks[currentIndex]();
        results[currentIndex] = { status: 'fulfilled', value };
      } catch (reason) {
        results[currentIndex] = { status: 'rejected', reason };
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, tasks.length) }, () => worker());
  await Promise.all(workers);
  return results;
}
