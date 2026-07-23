export class AFXError extends Error {
  constructor(code, message, cause) {
    super(message, { cause });
    this.name = 'AFXError';
    this.code = code;
  }
}
