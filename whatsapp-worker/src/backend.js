export class BackendClient {
  constructor({ baseUrl, token, logger, fetchImpl = fetch }) {
    this.baseUrl = baseUrl.replace(/\/$/, ''); this.token = token; this.logger = logger; this.fetch = fetchImpl;
  }
  async request(path, options = {}) {
    const response = await this.fetch(`${this.baseUrl}${path}`, { ...options, headers: { authorization: `Bearer ${this.token}`, 'content-type': 'application/json', ...options.headers }, signal: AbortSignal.timeout(15_000) });
    if (!response.ok) throw new Error(`backend ${options.method ?? 'GET'} ${path} failed: ${response.status}`);
    return response.status === 204 ? undefined : response.json();
  }
  accounts() { return this.request('/api/internal/accounts').then((data) => data.items ?? []); }
  state(id, payload) { return this.request(`/api/internal/accounts/${encodeURIComponent(id)}/state`, { method: 'POST', body: JSON.stringify(payload) }); }
  message(payload) { return this.request('/api/internal/messages', { method: 'POST', body: JSON.stringify(payload) }); }
}
