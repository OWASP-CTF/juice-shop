app.get('/metrics', security.denyAll(), utils.asyncHandler(metrics.serveMetrics()))
