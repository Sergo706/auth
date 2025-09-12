export interface Reasons {
    missingHeaders: 'Missing auth headers';
    unknownClient: 'Unknown client';
    timestamp: 'Stale timestamp';
    buffer: 'Buffer Doesn\'t match';
}

export const reasons: Reasons = {
    missingHeaders: 'Missing auth headers',
    unknownClient: 'Unknown client',
    timestamp: 'Stale timestamp',
    buffer: 'Buffer Doesn\'t match',
};