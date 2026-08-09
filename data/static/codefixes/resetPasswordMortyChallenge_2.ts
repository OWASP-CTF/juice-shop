/* Rate limiting */
  /* Only trust as many proxy hops as are actually deployed in front of us. Trusting
     every hop would let a client dictate req.ip through X-Forwarded-For and thereby
     reset its own rate limit counter at will. */
  app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS ?? 0))
  app.use('/rest/user/reset-password', rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
    keyGenerator ({ headers, ip }) { return headers['Forwarded'] ?? ip }
  }))