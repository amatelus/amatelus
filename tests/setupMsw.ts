import { setupServer, type SetupServerApi } from 'msw/node';
import { setupMswHandlers } from './setupMswHandlers';
import { TEST_BASE_URL } from './utils';

export function setupMsw(): SetupServerApi {
  const server = setupServer(
    ...setupMswHandlers(),
    ...setupMswHandlers({ baseURL: TEST_BASE_URL }),
  );

  server.listen({ onUnhandledRequest: 'error' });

  return server;
}
