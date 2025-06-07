import type { Prisma } from '@prisma/client';
import { prismaClient } from '../server/lib/prismaClient';
import { transaction } from '../server/lib/transaction';

async function someFn(_tx: Prisma.TransactionClient): Promise<void> {
  // seeder script
}

transaction('RepeatableRead', (tx) => Promise.all([someFn(tx)]))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => {
    void prismaClient.$disconnect();
  });
