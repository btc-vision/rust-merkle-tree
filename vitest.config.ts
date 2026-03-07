import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        include: ['__test__/**/*.{test,spec}.ts'],
        testTimeout: 600_000,
    },
});
