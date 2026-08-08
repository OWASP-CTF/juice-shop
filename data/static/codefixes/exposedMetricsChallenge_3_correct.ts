app.get('/metrics', security.isAuthorized(), security.isAdmin(), utils.asyncHandler(metrics.serveMetrics()))
