export class VeilcamsError extends Error {
  constructor(
    message: string,
    public readonly type: VeilcamsErrorType,
    public readonly retryable: boolean = false
  ) {
    super(message);
    this.name = 'VeilcamsError';
  }
}

export type VeilcamsErrorType =
  | 'ConfigurationError'
  | 'NetworkError'
  | 'PermissionError'
  | 'InvalidTargetError'
  | 'ScanError'
  | 'TimeoutError'
  | 'UnknownError';

export function classifyError(error: unknown): { type: VeilcamsErrorType; retryable: boolean; message: string } {
  if (error instanceof VeilcamsError) {
    return { type: error.type, retryable: error.retryable, message: error.message };
  }

  const message = error instanceof Error ? error.message : String(error);
  const messageLower = message.toLowerCase();

  if (/config|yaml|schema|validation/i.test(messageLower)) {
    return { type: 'ConfigurationError', retryable: false, message };
  }

  if (/permission|denied|eacces|forbidden/i.test(messageLower)) {
    return { type: 'PermissionError', retryable: false, message };
  }

  if (/invalid.*target|no.*host|unreachable/i.test(messageLower)) {
    return { type: 'InvalidTargetError', retryable: false, message };
  }

  if (/timeout|timed?\s*out|etimedout/i.test(messageLower)) {
    return { type: 'TimeoutError', retryable: true, message };
  }

  if (/econnrefused|econnreset|enotfound|enetunreach|socket/i.test(messageLower)) {
    return { type: 'NetworkError', retryable: true, message };
  }

  if (/nmap|scan|probe/i.test(messageLower)) {
    return { type: 'ScanError', retryable: true, message };
  }

  return { type: 'UnknownError', retryable: false, message };
}
