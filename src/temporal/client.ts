import { Connection, Client } from '@temporalio/client';
import { PROGRESS_QUERY_NAME, TASK_QUEUE } from './shared.js';
import type { PipelineInput, WorkflowProgress } from './shared.js';
import type { TargetSpec } from '../types/index.js';
import { ALL_CAMERA_PORTS } from '../constants.js';
import path from 'node:path';
import dotenv from 'dotenv';

dotenv.config();

function parseTargetsArg(arg: string): TargetSpec[] {
  // Supports:
  //   "192.168.1.100"              → single host, all camera ports
  //   "192.168.1.0/24"             → CIDR range, all camera ports
  //   "192.168.1.100:80,554"       → single host, specific ports
  //   "10.0.0.50;10.0.0.51"        → multiple hosts, all camera ports
  return arg.split(';').map((entry) => {
    const trimmed = entry.trim();

    // Check if ports are specified (look for colon that's NOT part of IPv6)
    // Simple heuristic: if it has a colon followed by digits, treat as host:ports
    const portMatch = trimmed.match(/^(.+):(\d[\d,]+)$/);

    let target: string;
    let ports: number[];

    if (portMatch) {
      target = portMatch[1];
      ports = portMatch[2].split(',').map((p) => parseInt(p.trim(), 10));
    } else {
      target = trimmed;
      ports = [...ALL_CAMERA_PORTS];
    }

    if (target.includes('/')) {
      return { range: target, ports };
    } else {
      return { host: target, ports };
    }
  });
}

async function promptForTarget(): Promise<string> {
  const { createInterface } = await import('node:readline');
  const rl = createInterface({ input: process.stdin, output: process.stdout });

  return new Promise((resolve) => {
    console.log('');
    console.log('\x1b[1mEnter target IP or range to scan:\x1b[0m');
    console.log('\x1b[36m  Examples:\x1b[0m');
    console.log('    192.168.1.100        (single camera)');
    console.log('    192.168.1.0/24       (entire subnet)');
    console.log('    10.0.0.50;10.0.0.51  (multiple hosts)');
    console.log('');
    rl.question('\x1b[32m> \x1b[0m', (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function main() {
  const args = process.argv.slice(2);

  // Parse arguments
  const parsedArgs: Record<string, string> = {};
  for (const arg of args) {
    const eqIdx = arg.indexOf('=');
    if (eqIdx > 0) {
      parsedArgs[arg.substring(0, eqIdx)] = arg.substring(eqIdx + 1);
    }
  }

  // Interactive prompt if no TARGETS provided
  let targetsStr = parsedArgs.TARGETS;
  if (!targetsStr) {
    targetsStr = await promptForTarget();
    if (!targetsStr) {
      console.error('Error: No target provided.');
      process.exit(1);
    }
    // Default to waiting when interactive
    if (!parsedArgs.WAIT) parsedArgs.WAIT = 'true';
  }

  const targets = parseTargetsArg(targetsStr);
  const configPath = parsedArgs.CONFIG ? path.resolve(parsedArgs.CONFIG) : undefined;
  const outputBase = parsedArgs.OUTPUT || './audit-logs';
  const pipelineTestingMode = parsedArgs.PIPELINE_TESTING === 'true';

  // Generate session ID and output path
  const timestamp = Date.now();
  const targetLabel = targets[0].host || targets[0].range || 'scan';
  const safeLabel = targetLabel.replace(/[/\\:]/g, '-');
  const sessionId = `${safeLabel}_veilcams-${timestamp}`;
  const outputPath = path.resolve(outputBase, sessionId);

  const input: PipelineInput = {
    targets,
    configPath,
    outputPath,
    pipelineTestingMode,
  };

  // Connect to Temporal
  const temporalAddress = process.env.TEMPORAL_ADDRESS || 'localhost:7233';
  const connection = await Connection.connect({ address: temporalAddress });
  const client = new Client({ connection });

  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║          VeilCams Pipeline               ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log(`Targets:  ${targets.map((t) => t.host || t.range).join(', ')}`);
  console.log(`Config:   ${configPath || '(defaults)'}`);
  console.log(`Output:   ${outputPath}`);
  console.log(`Testing:  ${pipelineTestingMode}`);
  console.log(`Session:  ${sessionId}`);
  console.log('');

  // Start workflow
  const handle = await client.workflow.start('veilcamsPipelineWorkflow', {
    taskQueue: TASK_QUEUE,
    workflowId: sessionId,
    args: [input],
    workflowRunTimeout: '4 hours',
  });

  console.log(`Workflow started: ${handle.workflowId}`);
  console.log(`Run ID: ${handle.firstExecutionRunId}`);
  console.log('');
  console.log('Monitor progress:');
  console.log(`  ./veilcams query ID=${handle.workflowId}`);
  console.log(`  ./veilcams logs ID=${handle.workflowId}`);
  console.log(`  Temporal UI: http://localhost:8233`);

  // If --wait flag, poll progress
  if (parsedArgs.WAIT === 'true' || process.env.VEILCAMS_WAIT === 'true') {
    console.log('');
    console.log('Waiting for completion...');

    const pollInterval = setInterval(async () => {
      try {
        const progress = await handle.query<WorkflowProgress>(PROGRESS_QUERY_NAME);
        const elapsed = Math.floor(progress.elapsedMs / 1000);
        const completed = progress.completedModules.length;
        const failed = progress.failedModules.length;
        console.log(
          `[${elapsed}s] Phase: ${progress.currentPhase} | Module: ${progress.currentModule || 'idle'} | Done: ${completed} | Failed: ${failed}`
        );
      } catch { /* query failed, workflow may be done */ }
    }, 15000);

    try {
      await handle.result();
      console.log('');
      console.log('Pipeline completed successfully.');
      console.log(`Report: ${outputPath}/deliverables/security_assessment_report.md`);
    } catch (error) {
      console.error('');
      console.error(`Pipeline failed: ${(error as Error).message}`);
    } finally {
      clearInterval(pollInterval);
    }
  }
}

main().catch((err) => {
  console.error('Client error:', err);
  process.exit(1);
});
