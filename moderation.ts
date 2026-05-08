import Anthropic from '@anthropic-ai/sdk';

const apiKey = process.env.ANTHROPIC_API_KEY;
const client = apiKey ? new Anthropic({ apiKey }) : null;

if (!client) {
  console.warn('[moderation] ANTHROPIC_API_KEY not set — content moderation disabled');
}

const SYSTEM_PROMPT = `You are a content moderator for a meditation and Buddhist practice community website.

Your job: decide whether a piece of user-submitted text should be ALLOWED or BLOCKED.

BLOCK only if the text contains:
- Profanity or vulgar language (including obvious l33t-speak / character substitutions like f*ck, sh1t, b!tch)
- Slurs targeting race, ethnicity, religion, gender, sexuality, or disability
- Sacrilegious mockery of religious figures, deities, or sacred concepts
- Hateful content directed at people, groups, or beliefs
- Threats, harassment, or incitement of violence against real people
- Sexual content
- Doxxing or personal attacks

ALLOW everything else, including:
- Normal conversation, questions, opinions
- Religious and philosophical discussion (including criticism)
- Mentions of historical violence, suffering, or death in educational/contemplative context
- Discussion of Buddhist concepts that may include words like "death," "kill," "demon" used contextually
- Edgy humor, sarcasm, mild frustration
- Disagreement and debate
- Sanskrit, Pali, or other religious terminology

When in doubt, ALLOW. False positives are worse than false negatives.

Respond with ONLY a JSON object on a single line, no markdown:
{"decision":"ALLOW"} or {"decision":"BLOCK","reason":"<short user-facing reason>"}`;

const cache = new Map<string, { ok: boolean; reason?: string; expiresAt: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000;

function cacheKey(text: string): string {
  return text.trim().toLowerCase().slice(0, 500);
}

export interface ModerationResult {
  ok: boolean;
  reason?: string;
}

export async function moderate(text: string): Promise<ModerationResult> {
  const trimmed = (text ?? '').trim();
  if (!trimmed) return { ok: true };
  if (!client) return { ok: true };

  const key = cacheKey(trimmed);
  const cached = cache.get(key);
  if (cached && cached.expiresAt > Date.now()) {
    return { ok: cached.ok, reason: cached.reason };
  }

  try {
    const response = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 100,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: trimmed.slice(0, 4000) }],
    });

    const block = response.content.find((c) => c.type === 'text');
    const raw = block && block.type === 'text' ? block.text.trim() : '';

    let parsed: { decision?: string; reason?: string } = {};
    try {
      parsed = JSON.parse(raw);
    } catch {
      const match = raw.match(/\{[^}]*\}/);
      if (match) {
        try {
          parsed = JSON.parse(match[0]);
        } catch {
          // fall through
        }
      }
    }

    const result: ModerationResult =
      parsed.decision === 'BLOCK'
        ? { ok: false, reason: parsed.reason || 'Content violates community guidelines' }
        : { ok: true };

    cache.set(key, { ...result, expiresAt: Date.now() + CACHE_TTL_MS });
    return result;
  } catch (err) {
    console.error('[moderation] API error, allowing through:', err);
    return { ok: true };
  }
}

export async function moderateMany(
  fields: Record<string, string | null | undefined>
): Promise<ModerationResult> {
  const combined = Object.values(fields)
    .filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
    .join('\n---\n');
  if (!combined) return { ok: true };
  return moderate(combined);
}
