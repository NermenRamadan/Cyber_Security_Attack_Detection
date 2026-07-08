import type { WebhookRequest, AttackResponse } from '@/types';

const N8N_WEBHOOK_URL = 'http://localhost:5678/webhook/security-chatbot';
const N8N_TEST_WEBHOOK_URL = 'http://localhost:5678/webhook-test/security-chatbot';

export async function sendToN8N(request: WebhookRequest): Promise<AttackResponse> {
  // Try production webhook first
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(N8N_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    return data as AttackResponse;
  } catch (error) {
    console.warn('Production webhook failed, trying test webhook:', error);

    // Try test webhook
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(N8N_TEST_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return data as AttackResponse;
    } catch (testError) {
  console.error('Both production and test webhooks failed:', testError);

  throw new Error('Unable to connect to n8n webhook.');
   }
  }
}


