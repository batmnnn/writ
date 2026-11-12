import type { S3PutRequest, S3Store } from "../src/host/s3-committer";

/** In-memory ledger bucket. PUT honours If-None-Match: *. Like the real store, no clock means every call throws. */
export class FakeS3Store implements S3Store {
  readonly objects = new Map<string, string>();
  readonly puts: S3PutRequest[] = [];
  /** Forced status for every PUT, for example 412 or 500. */
  putStatus: number | undefined;
  listFails = false;
  clock: () => Date | undefined = () => new Date(0);

  private need(): void {
    if (this.clock() === undefined) throw new Error("no trusted time to sign the request");
  }

  async putObject(req: S3PutRequest) {
    this.need();
    this.puts.push(req);
    if (this.putStatus !== undefined) return { status: this.putStatus };
    if (this.objects.has(req.key)) return { status: 412 };
    this.objects.set(req.key, req.body);
    return { status: 200 };
  }

  async listKeys(_bucket: string, prefix: string) {
    this.need();
    if (this.listFails) throw new Error("list refused with status 403");
    return [...this.objects.keys()].filter((k) => k.startsWith(prefix)).sort();
  }

  async getObject(_bucket: string, key: string) {
    this.need();
    return this.objects.get(key);
  }

  /** Bodies of the checkpoint objects under a prefix, oldest first. */
  checkpoints(prefix = "checkpoints/v2/") {
    return [...this.objects.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([, v]) => JSON.parse(v) as { seq: number; head: string; entry: { kind: string; payload: Record<string, unknown> }; signature: string });
  }
}
