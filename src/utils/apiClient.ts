import { $fc } from 'src/app/api/health/frourio.client';

export const apiClient = $fc({ init: { credentials: 'same-origin' } });
