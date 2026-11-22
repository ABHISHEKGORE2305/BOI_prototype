import { remediationSteps } from '../lib/remediation';
import { riskLevel, shortFeatureName } from '../lib/format';

const base = {
  status: 'completed',
  sha256: 'ab'.repeat(32),
  apk_info: { package: 'com.evil.app' },
};

test('malicious verdict yields indicator-specific steps', () => {
  const steps = remediationSteps({
    ...base,
    verdict: 'malicious',
    features: { permissions: ['SEND_SMS', 'RECEIVE_BOOT_COMPLETED'], api_calls: ['DexClassLoader'] },
  });

  const text = steps.join('\n');
  expect(text).toContain('Block package com.evil.app');
  expect(text).toContain('SMS');
  expect(text).toContain('restarts at boot');
  expect(text).toContain('sandbox');
  expect(text).not.toContain('root');
});

test('benign verdict does not recommend blocking', () => {
  const steps = remediationSteps({ ...base, verdict: 'benign', features: {} });

  expect(steps.join('\n')).not.toContain('Block package');
});

test('no steps for unfinished tasks', () => {
  expect(remediationSteps({ status: 'processing' })).toEqual([]);
});

test('risk levels follow the verdict', () => {
  expect(riskLevel(95, 'malicious').tone).toBe('critical');
  expect(riskLevel(70, 'malicious').tone).toBe('high');
  expect(riskLevel(40, 'benign').tone).toBe('medium');
  expect(riskLevel(3, 'benign').tone).toBe('clean');
});

test('feature names are shortened for charts', () => {
  expect(shortFeatureName('android.intent.action.BOOT_COMPLETED')).toBe('intent:BOOT_COMPLETED');
  expect(shortFeatureName('Ljava.lang.Class.forName')).toBe('java.lang.Class.forName');
});
