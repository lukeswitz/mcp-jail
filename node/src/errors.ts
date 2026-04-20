export class JailBlocked extends Error {
  readonly reason: string;
  readonly fingerprint: string;
  readonly argv: string[];

  constructor(reason: string, fingerprint: string, argv: readonly string[]) {
    const hint = fingerprint.length >= 12 ? `\n  mcp-jail approve ${fingerprint.slice(0, 12)}` : '';
    super(`mcp-jail blocked spawn: ${reason}\n  argv: ${JSON.stringify(argv)}${hint}`);
    this.name = 'JailBlocked';
    this.reason = reason;
    this.fingerprint = fingerprint;
    this.argv = [...argv];
  }
}
