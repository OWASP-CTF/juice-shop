app.get('/metrics', utils.asyncHandler(metrics.serveMetrics()))
