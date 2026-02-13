import { Connection, Client } from '@temporalio/client';
import { PROGRESS_QUERY_NAME } from './shared.js';
import type { WorkflowProgress } from './shared.js';
import dotenv from 'dotenv';

dotenv.config();

async function main() {
  const workflowId = process.argv[2];

  if (!workflowId) {
    console.error('Usage: node query.js <workflow-id>');
    process.exit(1);
  }

  const temporalAddress = process.env.TEMPORAL_ADDRESS || 'localhost:7233';
  const connection = await Connection.connect({ address: temporalAddress });
  const client = new Client({ connection });

  const handle = client.workflow.getHandle(workflowId);

  try {
    const progress = await handle.query<WorkflowProgress>(PROGRESS_QUERY_NAME);
    const elapsed = Math.floor(progress.elapsedMs / 1000);
    const minutes = Math.floor(elapsed / 60);
    const seconds = elapsed % 60;

    console.log('');
    console.log('╔══════════════════════════════════════════╗');
    console.log('║       VeilCams Pipeline Progress         ║');
    console.log('╚══════════════════════════════════════════╝');
    console.log(`Workflow:   ${workflowId}`);
    console.log(`Phase:      ${progress.currentPhase}`);
    console.log(`Module:     ${progress.currentModule || 'idle'}`);
    console.log(`Elapsed:    ${minutes}m ${seconds}s`);
    console.log(`Completed:  ${progress.completedModules.join(', ') || 'none'}`);
    console.log(`Failed:     ${progress.failedModules.join(', ') || 'none'}`);
    console.log('');
  } catch (error) {
    // Check if workflow is completed
    try {
      const description = await handle.describe();
      console.log(`Workflow status: ${description.status.name}`);
      if (description.status.name === 'COMPLETED') {
        console.log('Pipeline completed. Check the output directory for results.');
      } else if (description.status.name === 'FAILED') {
        console.log('Pipeline failed. Check worker logs for details.');
      }
    } catch {
      console.error(`Could not find workflow: ${workflowId}`);
      console.error('Ensure the workflow ID is correct and Temporal is running.');
    }
  }
}

main().catch((err) => {
  console.error('Query error:', err);
  process.exit(1);
});
