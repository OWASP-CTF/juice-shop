describe('JWT authentication', () => {
  it('rejects an unsigned token', () => {
    cy.request({
      url: '/api/Users',
      headers: {
        Authorization: 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.'
      },
      failOnStatusCode: false
    }).its('status').should('eq', 401)
  })

  it('rejects a token HMAC-signed with the public RSA key', () => {
    cy.request({
      url: '/api/Users',
      headers: {
        Authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgzMDM3NzExfQ.gShXDT5TrE5736mpIbfVDEcQbLfteJaQUG7Z0PH8Xc8'
      },
      failOnStatusCode: false
    }).its('status').should('eq', 401)
  })
})
