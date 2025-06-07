import { PrismaClient } from '@prisma/client';
import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { spawn } from 'child_process';
import type { SetupServerApi } from 'msw/lib/node';
import type * as routerMock from 'next-router-mock';
import type * as nextNavigation from 'next/navigation';
import { ulid } from 'ulid';
import { afterAll, afterEach, beforeAll, beforeEach, vi } from 'vitest';
import { setupMsw } from './setupMsw';
import { patchFilePrototype } from './setupMswHandlers';

function createPrismaClient(): PrismaClient {
  return new PrismaClient({ datasources: { db: { url: process.env.DATABASE_URL } } });
}

vi.mock('server/service/prismaClient', async () => {
  process.env.DATABASE_URL = process.env.DATABASE_URL!.replace(/[^/]+$/, `test-${ulid()}`);

  return { prismaClient: createPrismaClient() };
});

// https://github.com/vercel/next.js/discussions/63100#discussioncomment-8737391
vi.mock('next/navigation', async (importOriginal) => {
  const actual = await importOriginal<typeof nextNavigation>();
  const { useRouter } = await vi.importActual<typeof routerMock>('next-router-mock');
  const usePathname = vi.fn().mockImplementation(() => {
    const router = useRouter();
    return router.pathname;
  });
  const useSearchParams = vi.fn().mockImplementation(() => {
    const router = useRouter();

    // eslint-disable-next-line @typescript-eslint/no-base-to-string
    return new URLSearchParams(router.query.toString());
  });

  return {
    ...actual,
    useRouter: (): { replace: (_href: string) => Promise<void> } => ({
      replace: (_href: string) => Promise.resolve(),
    }),
    usePathname,
    useSearchParams,
  };
});

let server: SetupServerApi;

beforeAll(() => {
  server = setupMsw();
  global.alert = (message: string): void => console.error(message);

  patchFilePrototype();
});

beforeEach(async () => {
  await new Promise((resolve, reject) => {
    const proc = spawn('npx', ['prisma', 'migrate', 'reset', '--force'], {
      // stdio: 'inherit',
    });

    proc.once('close', resolve);
    proc.once('error', reject);
  });
}, 20000);

afterEach(async () => {
  await createPrismaClient().$disconnect();

  cleanup();
  vi.clearAllMocks();

  if ('document' in global) {
    localStorage.clear();
    document.cookie.split(';').forEach((cookie) => {
      document.cookie = `${cookie.split('=')[0].trim()}=; Max-Age=0; path=/`;
    });
  }
});

afterAll(async () => {
  server.close();
});
