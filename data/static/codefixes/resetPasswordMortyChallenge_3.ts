/* Rate limiting */
  /* Only trust as many proxy hops as are actually deployed in front of us. Trusting
     every hop would let a client dictate req.ip through X-Forwarded-For and thereby
     reset its own rate limit counter at will. */
  app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS ?? 0))
  app.use('/rest/user/reset-password', rateLimit({
    windowMs: 3 * 60 * 1000,
    max: 10,
    keyGenerator ({ headers, ip }) { return headers['X-Forwarded-For'] ?? ip }
  }))