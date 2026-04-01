import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { bootstrapApp } from '../../src/service.js';
import { config } from '../configs/config.js';
import { Express } from 'express';

describe('Health', () => {
    let app: Express;

    beforeAll(async () => {
        app = await bootstrapApp(config);
    });

    it('should respond with 200 when the full app is build', async () => {
        const res = await request(app).get('/health');
        expect(res.status).toBe(200);
        expect(res.text).toBe('OK');
    });
});