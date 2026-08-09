describe('/#/administration', () => {
  beforeEach(() => {
    cy.login({
      email: 'admin',
      password: 'admin123'
    })
  })
  // Regression test: the administration endpoints are now guarded server-side by
  // security.isAdmin() (see server.ts), so merely reaching /#/administration proves
  // nothing about access control and the "Admin Section" challenge can never be solved.
  describe('challenge "adminSection"', () => {
    it('should be possible to access administration section with admin user without solving the challenge', () => {
      cy.visit('/#/administration')
      cy.url().should('match', /\/administration/)
      cy.wait(1000) // added for debugging the CI
      cy.request({
        method: 'GET',
        url: '/api/Challenges/?name=Admin Section',
        timeout: 60000
      }).then((response) => {
        const challenge = response.body.data[0]
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        expect(challenge.solved).to.be.false
      })
    })
  })

  describe('challenge "fiveStarFeedback"', () => {
    it('should be possible for any admin user to delete feedback', () => {
      cy.visit('/#/administration')
      cy.wait(1000)
      cy.get('.mat-mdc-cell.mat-column-remove > button').first().click()
      cy.expectChallengeSolved({ challenge: 'Five-Star Feedback' })
    })
  })
})

describe('/#/administration as a non-admin user', () => {
  beforeEach(() => {
    cy.login({
      email: 'jim',
      password: 'ncc-1701'
    })
  })

  // The client-side AdminGuard is only a UX affordance. These assertions prove the
  // administrative data is unreachable even when that guard is bypassed entirely.
  it('should not be able to read the user list', () => {
    cy.window().then((window) => {
      cy.request({
        method: 'GET',
        url: '/rest/user/authentication-details',
        headers: { Authorization: `Bearer ${window.localStorage.getItem('token')}` },
        failOnStatusCode: false
      }).its('status').should('equal', 403)
    })
  })

  it('should not be able to read user records', () => {
    cy.window().then((window) => {
      cy.request({
        method: 'GET',
        url: '/api/Users',
        headers: { Authorization: `Bearer ${window.localStorage.getItem('token')}` },
        failOnStatusCode: false
      }).its('status').should('equal', 403)
    })
  })

  it('should not be able to delete feedback', () => {
    cy.window().then((window) => {
      cy.request({
        method: 'DELETE',
        url: '/api/Feedbacks/1',
        headers: { Authorization: `Bearer ${window.localStorage.getItem('token')}` },
        failOnStatusCode: false
      }).its('status').should('equal', 403)
    })
  })
})
