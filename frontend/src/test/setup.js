import '@testing-library/jest-dom/vitest';
import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';

// RTL: уборка DOM между тестами (без globals в vitest-конфиге cleanup не автоматический)
afterEach(cleanup);
