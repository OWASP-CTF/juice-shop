// routes/currentUser.ts now allowlists the `fields` parameter of
// GET /rest/user/whoami, so the Password Hash Leak challenge is unsolvable
// by design. This case asserts the closure so the fix cannot silently
// regress.
describe('challenge "Password Hash Leak" (patched)', () => {
  beforeEach(() => {
    cy.login({ email: 'admin@juice-sh.op', password: 'admin123' })
  })

  it('should not leak the password hash via fields parameter', () => {
    cy.request({
      method: 'GET',
      url: '/rest/user/whoami?fields=id,email,password',
      headers: {
        // Cypress automatically handles cookies after cy.login
      }
    }).then((res) => {
      expect(res.status).to.equal(200)
      expect(res.body.user).to.not.have.property('password')
      expect(res.body.user.id).to.be.a('number')
      expect(res.body.user.email).to.be.a('string')
    })
  })
})
