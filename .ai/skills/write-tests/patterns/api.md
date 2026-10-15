## Pattern: SQL injection regression tests

Negative tests that prove injection payloads are rejected. Mirror `test/api/login.test.ts`.

```typescript
const payloads = [
  "' or '1'='1' --",
  "admin@juice-sh.op'--",
  "' OR 1=1 --",
  "'; DROP TABLE Users; --"
]

for (const email of payloads) {
  void it(`POST login rejects injection payload: ${email}`, async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email, password: 'x' })
    assert.equal(res.status, 401)
    assert.equal(res.body.authentication, undefined)
  })
}

void it('POST login rejects non-string credentials', async () => {
  const res = await request(app)
    .post('/rest/user/login')
    .set({ 'content-type': 'application/json' })
    .send({ email: { $ne: null }, password: ['x'] })
  assert.equal(res.status, 401)
})
```