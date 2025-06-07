import { config } from 'dotenv';
import { z } from 'zod';

const NODE_ENV = z
  .enum(['test', 'development', 'production', 'cli'])
  .default('cli')
  .parse(process.env.NODE_ENV);

config();

export { NODE_ENV };
