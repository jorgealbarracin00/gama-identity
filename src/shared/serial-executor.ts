import { AsyncLocalStorage } from "node:async_hooks";

/** Serial, reentrant only within the currently live transaction context. */
export class SerialExecutor {
  private tail: Promise<void> = Promise.resolve();
  private readonly context = new AsyncLocalStorage<{ active: boolean }>();
  async execute<T>(work: () => Promise<T>): Promise<T> {
    if (this.context.getStore()?.active) return work();
    let release!: () => void;
    const previous=this.tail;
    this.tail=new Promise<void>(resolve => { release=resolve; });
    await previous;
    const scope={active:true};
    try { return await this.context.run(scope,work); }
    finally { scope.active=false; release(); }
  }
}
