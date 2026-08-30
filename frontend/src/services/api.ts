import type { Environment, AttackPath } from '../types';
const base = import.meta.env.VITE_API_URL || '/api';
export const api = {
  environment: () => fetch(`${base}/environments/demo`).then(r => r.json() as Promise<Environment>),
  analyze: (entry_point: string, target?: string) => fetch(`${base}/environments/demo/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ entry_point, target, max_depth: 7 })
  }).then(r => r.json() as Promise<{ paths: AttackPath[]; summary: any; recommendations: any[] }>),
  whatIf: (remove_id: string, remove_type: string, entry_point: string, target?: string) => fetch(`${base}/environments/demo/what-if`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ remove_id, remove_type, entry_point, target, max_depth: 7 })
  }).then(r => r.json())
};
