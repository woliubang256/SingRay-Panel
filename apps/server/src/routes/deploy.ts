// 部署路由:单机双核心/单核心 + 一键部署全部(后台任务 + 轮询进度)
import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import { getDb } from '../db/client.js';
import { deployAll, deployServerBothCores, planDeployments, type DeployScope } from '../services/deployAll.js';
import { listPendingDeploys } from '../services/deployState.js';
import { listDeployAudits } from '../services/deployAudit.js';
import { genRandomHex } from '../core/crypto.js';
import type { MachineDeployResult } from '../services/deployAll.js';

const idParam = z.object({ id: z.coerce.number().int() });
const coreSchema = z.object({ core: z.enum(['singbox', 'xray']).optional() });

interface JobMachine {
  serverId: number;
  name: string;
  core?: 'singbox' | 'xray';
  status: 'pending' | 'done';
  result?: MachineDeployResult;
}

interface DeployJob {
  id: string;
  scope: DeployScope;
  startedAt: number;
  done: boolean;
  machines: JobMachine[];
}

/** 内存任务表(单管理员自用;进程重启即清,无持久化需求) */
const jobs = new Map<string, DeployJob>();

function pruneJobs(): void {
  const cutoff = Date.now() - 3600_000;
  for (const [id, j] of jobs) if (j.done && j.startedAt < cutoff) jobs.delete(id);
}

export default async function deployRoutes(app: FastifyInstance): Promise<void> {
  /** 待部署清单(服务器页"有未下发变更"横幅) */
  app.get('/pending', async () => listPendingDeploys(getDb()));

  /** 部署审计:最近 N 次部署结果(进程重启也查得到) */
  app.get('/audits', async (req) => {
    const q = z
      .object({ serverId: z.coerce.number().int().optional(), limit: z.coerce.number().int().min(1).max(200).optional() })
      .parse(req.query ?? {});
    return listDeployAudits(getDb(), q.serverId, q.limit ?? 50);
  });

  /** 两种范围共用任务锁和计划快照,前端进度与真正下发的机器/核心一致。 */
  const startJob = (scope: DeployScope, reply: FastifyReply) => {
    pruneJobs();
    const running = [...jobs.values()].find((j) => !j.done);
    if (running) {
      return reply.code(409).send({ error: '已有部署任务进行中', jobId: running.id });
    }
    const db = getDb();
    const targets = planDeployments(db, scope);
    const job: DeployJob = {
      id: genRandomHex(6),
      scope,
      startedAt: Date.now(),
      done: targets.length === 0,
      machines: targets.map((s) => ({ ...s, status: 'pending' })),
    };
    jobs.set(job.id, job);
    if (targets.length) void (async () => {
      await deployAll(db, undefined, (result) => {
        const m = job.machines.find((x) => x.serverId === result.serverId);
        if (m) {
          m.result = result;
          m.status = 'done';
        }
      }, { targets });
      job.done = true;
    })().catch(() => {
      job.done = true;
    });
    return { jobId: job.id, scope, machines: job.machines };
  };

  app.post('/all', async (_req, reply) => startJob('all', reply));
  app.post('/pending', async (_req, reply) => startJob('pending', reply));

  /** 部署任务进度 */
  app.get('/status/:jobId', async (req, reply) => {
    const { jobId } = z.object({ jobId: z.string().min(1) }).parse(req.params);
    const job = jobs.get(jobId);
    if (!job) return reply.code(404).send({ error: '任务不存在或已过期' });
    return { id: job.id, scope: job.scope, done: job.done, machines: job.machines };
  });

  /** 单机部署(body.core 缺省 = sing-box + xray 都部署;同步等待) */
  app.post('/:id', async (req) => {
    const { id } = idParam.parse(req.params);
    const { core } = coreSchema.parse(req.body ?? {});
    return deployServerBothCores(getDb(), id, undefined, core);
  });
}
