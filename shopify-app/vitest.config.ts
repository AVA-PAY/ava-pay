import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // .tsx as well: root.test.tsx renders the document to assert the App
    // Bridge script really does come out first in the head.
    include: ['app/**/*.test.ts', 'app/**/*.test.tsx'],
    environment: 'node',
    globals: false,
    reporters: 'default',
  },
});
