import { NativeConnection, Worker, bundleWorkflowCode } from '@temporalio/worker';
import { fileURLToPath } from 'node:url';
import * as activities from './activities.js';
import { TASK_QUEUE } from './shared.js';
import dotenv from 'dotenv';

dotenv.config();

async function main() {
  const temporalAddress = process.env.TEMPORAL_ADDRESS || 'localhost:7233';

  console.log('╔══════════════════════════════════════════╗');
  console.log('║       VeilCams Worker Starting...        ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log(`Temporal: ${temporalAddress}`);
  console.log(`Task Queue: ${TASK_QUEUE}`);

  const connection = await NativeConnection.connect({ address: temporalAddress });

  const workflowBundle = await bundleWorkflowCode({
    workflowsPath: fileURLToPath(new URL('./workflows.js', import.meta.url)),
  });

  const worker = await Worker.create({
    connection,
    namespace: 'default',
    workflowBundle,
    activities,
    taskQueue: TASK_QUEUE,
    maxConcurrentActivityTaskExecutions: 10,
  });

  console.log('Worker started. Listening for workflows...');

  await worker.run();
}

main().catch((err) => {
  console.error('Worker failed to start:', err);
  process.exit(1);
});
