import { prismaClient } from 'server/lib/prismaClient';
import { createRoute } from './frourio.server';

function throwError(label: string) {
  return (e: Error): never => {
    /* v8 ignore next 1 */
    throw new Error(`${label} ${e.message}`);
  };
}

export const { GET } = createRoute({
  get: async () => ({
    status: 200,
    body: await Promise.all([
      prismaClient.$queryRaw`SELECT CURRENT_TIMESTAMP;`.catch(throwError('DB')),
    ]).then(() => 'ok'),
  }),
});
