/**
 * Controle de uso em memória. Janela deslizante por minuto e contador diário (UTC).
 * Protege a cota da conta VirusTotal e limita cada cliente individualmente.
 */
export class RateLimiter {
  constructor({ perMinute, perDay = Infinity, now = () => Date.now() }) {
    this.perMinute = perMinute;
    this.perDay = perDay;
    this.now = now;
    this.minute = [];
    this.day = { key: '', count: 0 };
  }

  #dayKey(ms) {
    return new Date(ms).toISOString().slice(0, 10);
  }

  /** Retorna `{ allowed: true }` ou `{ allowed: false, retryAfter }` (segundos). */
  take() {
    const t = this.now();
    this.minute = this.minute.filter((ts) => t - ts < 60_000);
    const key = this.#dayKey(t);
    if (this.day.key !== key) this.day = { key, count: 0 };

    if (this.day.count >= this.perDay) {
      const tomorrow = Date.parse(`${key}T00:00:00.000Z`) + 86_400_000;
      return { allowed: false, retryAfter: Math.ceil((tomorrow - t) / 1000), reason: 'daily_quota' };
    }
    if (this.minute.length >= this.perMinute) {
      const retryAfter = Math.max(1, Math.ceil((60_000 - (t - this.minute[0])) / 1000));
      return { allowed: false, retryAfter, reason: 'minute_quota' };
    }
    this.minute.push(t);
    this.day.count += 1;
    return { allowed: true };
  }

  remainingToday() {
    const key = this.#dayKey(this.now());
    if (this.day.key !== key) return this.perDay === Infinity ? null : this.perDay;
    return this.perDay === Infinity ? null : Math.max(0, this.perDay - this.day.count);
  }
}
