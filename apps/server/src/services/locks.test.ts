import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { withServerLock, holdsServerLock, resetServerLocks } from './locks.js';

const tick = () => new Promise((r) => setTimeout(r, 0));

describe('per-server lock', () => {
  beforeEach(() => resetServerLocks());
  afterEach(() => vi.useRealTimers());

  it('拿到锁后执行超过诊断的 10 秒等待期限也不误报占用', async () => {
    vi.useFakeTimers();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    let entered = false, settled = false;
    const result = withServerLock(8, async () => {
      entered = true;
      await gate;
      return 'diagnosis complete';
    }, { waitMs: 10_000 }).then(
      value => { settled = true; return { value }; },
      error => { settled = true; return { error }; },
    );
    await vi.advanceTimersByTimeAsync(10_001);
    const settledWhileRunning = settled;
    release();
    const outcome = await result;
    expect(entered).toBe(true);
    expect(settledWhileRunning).toBe(false);
    expect(outcome).toEqual({ value: 'diagnosis complete' });
  });

  it('排队在期限内获得锁后停止等待计时，不限制后续执行时长', async () => {
    vi.useFakeTimers();
    let releaseOwner!: () => void, releaseWaiter!: () => void;
    const ownerGate = new Promise<void>(resolve => { releaseOwner = resolve; });
    const waiterGate = new Promise<void>(resolve => { releaseWaiter = resolve; });
    const owner = withServerLock(8, () => ownerGate);
    let started = false, settled = false;
    const waiter = withServerLock(8, async () => {
      started = true;
      await waiterGate;
      return 'done';
    }, { waitMs: 10_000 }).then(
      value => { settled = true; return { value }; },
      error => { settled = true; return { error }; },
    );
    await vi.advanceTimersByTimeAsync(8_000);
    releaseOwner(); await owner;
    await vi.advanceTimersByTimeAsync(12_000);
    const settledWhileRunning = settled;
    releaseWaiter();
    const outcome = await waiter;
    expect(started).toBe(true);
    expect(settledWhileRunning).toBe(false);
    expect(outcome).toEqual({ value: 'done' });
  });

  it('等待者超时后新操作仍必须等待原持有者释放，超时任务不补跑', async () => {
    vi.useFakeTimers();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const order: string[] = [];
    const owner = withServerLock(8, async () => { order.push('owner:start'); await gate; order.push('owner:end'); });
    const expired = withServerLock(8, async () => { order.push('expired'); }, { waitMs: 20 })
      .catch(error => error.status);
    await vi.advanceTimersByTimeAsync(20);
    const expiredStatus = await expired;
    const next = withServerLock(8, async () => { order.push('next'); });
    await vi.advanceTimersByTimeAsync(1);
    const orderBeforeRelease = [...order];
    release(); await Promise.all([owner, next]);
    expect(expiredStatus).toBe(409);
    expect(orderBeforeRelease).toEqual(['owner:start']);
    expect(order).toEqual(['owner:start', 'owner:end', 'next']);
    await expect(withServerLock(8, async () => 'available')).resolves.toBe('available');
  });

  it('长任务保留实际执行错误，不被等待超时替换且后续请求可继续', async () => {
    vi.useFakeTimers();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const result = withServerLock(8, async () => { await gate; throw new Error('SSH command timeout'); }, { waitMs: 20 })
      .catch(error => error.message);
    await vi.advanceTimersByTimeAsync(50);
    release();
    expect(await result).toBe('SSH command timeout');
    await expect(withServerLock(8, async () => 'recovered')).resolves.toBe('recovered');
  });

  it('同一台机器的操作串行执行', async () => {
    const order: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });

    const a = withServerLock(1, async () => {
      order.push('a:start');
      await gate;
      order.push('a:end');
    });
    const b = withServerLock(1, async () => {
      order.push('b:start');
    });

    await tick();
    expect(order).toEqual(['a:start']); // b 还在排队
    release();
    await Promise.all([a, b]);
    expect(order).toEqual(['a:start', 'a:end', 'b:start']);
  });

  it('不同机器并行,互不阻塞', async () => {
    const order: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const a = withServerLock(1, async () => {
      await gate;
      order.push('a');
    });
    const b = withServerLock(2, async () => {
      order.push('b');
    });
    await b; // 机器 1 还卡着,机器 2 已经完成
    expect(order).toEqual(['b']);
    release();
    await a;
    expect(order).toEqual(['b', 'a']);
  });

  it('同异步链内嵌套调用复用外层锁(部署 → 自动安装核心),不会自锁死', async () => {
    const r = await withServerLock(1, async () => {
      expect(holdsServerLock(1)).toBe(true);
      return withServerLock(1, async () => 'nested-ok');
    });
    expect(r).toBe('nested-ok');
    expect(holdsServerLock(1)).toBe(false);
  });

  it('排队超时抛 409,且不会在超时后偷偷执行', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    let ranLate = false;
    const a = withServerLock(1, async () => {
      await gate;
    });
    const b = withServerLock(
      1,
      async () => {
        ranLate = true;
        return 'late';
      },
      { waitMs: 20 },
    );
    await expect(b).rejects.toThrow(/正在执行其他操作/);
    release();
    await a;
    await tick();
    expect(ranLate).toBe(false);
  });

  it('前一个操作抛错不影响后续操作', async () => {
    await expect(
      withServerLock(2, async () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    await expect(withServerLock(2, async () => 'ok')).resolves.toBe('ok');
  });
});
