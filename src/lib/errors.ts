export class AnalysisError extends Error {
  constructor(
    message: string,
    readonly stage: string
  ) {
    super(message);
    this.name = 'AnalysisError';
  }
}

export function asUserMessage(error: unknown): string {
  if (error instanceof AnalysisError) {
    return `${error.stage}: ${error.message}`;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return 'An unknown analysis error occurred.';
}
