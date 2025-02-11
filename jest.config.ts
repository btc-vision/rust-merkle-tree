import type { Config } from '@jest/types';
import { BabelConfig } from 'ts-jest';

const esModules = [
    'chalk',
    'supports-color',
    '@btc-vision/bsi-common',
    '@btc-vision/bsi-db',
    '@btc-vision/logger',
    '@btc-vision/transaction',
    'opnet',
].join('|');

const babelConfig: BabelConfig = {
    presets: ['@babel/preset-env'],
    plugins: [['babel-plugin-transform-import-meta', { module: 'ES6' }]],
};

// @ts-ignore
const config: Config.InitialOptions = {
    verbose: true,
    rootDir: './',
    transform: {
        '\\.[jt]s?$': [
            'ts-jest',
            {
                useESM: true,
                tsconfig: { allowJs: true },
                babelConfig: babelConfig,
            },
        ],
    },
    modulePathIgnorePatterns: ['packages', 'build', 'node_modules', 'config', 'utils'],
    testMatch: [
        '<rootPath>/__test__/**/*.test.ts',
        '<rootPath>/__test__/*.test.ts',
        '<rootDir>/__test__/**/*.test.ts',
        '<rootDir>/__test__/*.test.ts',
    ],
    moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.[jt]s$': '$1',
    },
    moduleFileExtensions: ['js', 'jsx', 'ts', 'tsx', 'node'],
    moduleDirectories: ['node_modules', 'src', 'build'],
    testEnvironment: 'node',
    transformIgnorePatterns: [`/node_modules/(?!${esModules})`, `/build/`],
    preset: 'ts-jest/presets/js-with-babel',
};

export default config;
